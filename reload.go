// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	stdsyscall "syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/outputs"
)

// reloadConfiguration re-reads the config file passed with -c, rebuilds the
// output clients and atomically swaps them with the running ones. Env vars
// keep their precedence over file values, exactly like at startup.
//
// The whole read-and-swap is serialized by reloadMu so two concurrent
// triggers (file watcher and SIGHUP) can never apply a stale configuration
// over a newer one. A file read error aborts the reload and the running
// configuration is kept.
//
// Fields that can not be applied on the fly keep their startup values:
//   - listenaddress/listenport and the tlsserver block (the listeners are
//     not re-bound on reload),
//   - customfields/templatedfields/prometheus.extralabels and
//     otlp.metrics.extraattributes (the prometheus/OTLP label sets are
//     registered at startup and can not change cardinality at runtime).
func reloadConfiguration() {
	if configFilePath == "" {
		utils.Log(utils.WarningLvl, "", "No config file in use (-c), nothing to reload")
		return
	}

	reloadMu.Lock()
	defer reloadMu.Unlock()

	newConfig, err := reloadConfig()
	if err != nil {
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Reload aborted, keeping the current configuration: %v", err))
		return
	}
	if newConfig == nil {
		return
	}

	if newConfig.ListenAddress != config.ListenAddress || newConfig.ListenPort != config.ListenPort {
		utils.Log(utils.WarningLvl, "", "listenaddress/listenport changes require a restart, keeping the current listener")
		newConfig.ListenAddress = config.ListenAddress
		newConfig.ListenPort = config.ListenPort
	}
	if !reflect.DeepEqual(newConfig.TLSServer, config.TLSServer) {
		utils.Log(utils.WarningLvl, "", "tlsserver changes require a restart, keeping the current TLS configuration")
		newConfig.TLSServer = config.TLSServer
	}
	if !sameStringMap(newConfig.Customfields, config.Customfields) ||
		!sameStringMap(newConfig.Templatedfields, config.Templatedfields) ||
		newConfig.Prometheus.ExtraLabels != config.Prometheus.ExtraLabels ||
		newConfig.OTLP.Metrics.ExtraAttributes != config.OTLP.Metrics.ExtraAttributes {
		utils.Log(utils.WarningLvl, "", "customfields/templatedfields/prometheus.extralabels/otlp.metrics.extraattributes changes require a restart, keeping the current values")
		newConfig.Customfields = config.Customfields
		newConfig.Templatedfields = config.Templatedfields
		newConfig.Prometheus.ExtraLabels = config.Prometheus.ExtraLabels
		newConfig.Prometheus.ExtraLabelsList = config.Prometheus.ExtraLabelsList
		newConfig.OTLP.Metrics.ExtraAttributes = config.OTLP.Metrics.ExtraAttributes
		newConfig.OTLP.Metrics.ExtraAttributesList = config.OTLP.Metrics.ExtraAttributesList
	}

	oldOutputs := make([]string, len(outputs.EnabledOutputs))
	copy(oldOutputs, outputs.EnabledOutputs)

	config = newConfig
	nullClient.Config = newConfig
	initClientArgs.Config = newConfig
	initOutputs()

	utils.Log(utils.InfoLvl, "", fmt.Sprintf("Configuration reloaded, enabled outputs: %v -> %v", oldOutputs, outputs.EnabledOutputs))
}

// sameStringMap compares two string maps by content.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// watchConfigFile triggers a reload when the config file passed with -c is
// modified. The parent directory is watched instead of the file itself:
// editors usually save with a write-tmp-then-rename dance and Kubernetes
// updates ConfigMap volumes with a symlink swap, both replace the inode the
// file watch was registered on. Events are filtered on the file name and
// debounced (500ms) as a single save produces a burst of events.
func watchConfigFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Failed to create config file watcher: %v", err))
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(configFilePath)
	base := filepath.Base(configFilePath)
	// the file itself is watched for direct writes,
	if err := watcher.Add(configFilePath); err != nil {
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Failed to watch config file %s: %v", configFilePath, err))
		return
	}
	// and its parent directory for rename/symlink replacements (best effort,
	// some platforms only report directory events on Linux).
	if err := watcher.Add(dir); err != nil {
		utils.Log(utils.DebugLvl, "", fmt.Sprintf("Failed to watch config directory %s: %v", dir, err))
	}
	utils.Log(utils.InfoLvl, "", fmt.Sprintf("Watching config file for changes: %s", configFilePath))

	// reWatchAndReload re-registers the file watch (a rename/symlink swap
	// replaces the inode the watch was on) before reloading.
	reWatchAndReload := func() {
		if err := watcher.Add(configFilePath); err != nil {
			utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Failed to re-watch config file %s: %v", configFilePath, err))
		}
		reloadConfiguration()
	}

	var timer *time.Timer
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			// Kubernetes ConfigMap volumes swap the "..data" symlink on
			// update (via a "..data_tmp" rename), events carrying those
			// names must be honored too.
			eventBase := filepath.Base(event.Name)
			if eventBase != base && !strings.HasPrefix(eventBase, "..data") {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(500*time.Millisecond, reWatchAndReload)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Config file watcher error: %v", err))
		}
	}
}

// handleReloadSignals triggers a reload on SIGHUP, the conventional way to
// ask a daemon to reload its configuration.
func handleReloadSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, stdsyscall.SIGHUP)
	for range sigs {
		utils.Log(utils.InfoLvl, "", "Received SIGHUP, reloading configuration")
		reloadConfiguration()
	}
}

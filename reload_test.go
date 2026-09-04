// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/outputs"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// initTestGlobalsOnce protects the creation of the test globals.
var initTestGlobalsOnce sync.Once

// writeConfigFile writes content to a temp yaml file and points the global
// configFilePath at it, like a startup with -c would have done.
func writeConfigFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	configFilePath = path
}

// initTestGlobals mirrors the globals init() builds for the production
// binary (init() skips them for test binaries).
func initTestGlobals() {
	// zero values are enough: the reload tests never dispatch events, and this
	// avoids registering expvar/prometheus/OTLP collectors twice in the test
	// process (getInitStats/getInitPromStats would panic on duplicates).
	initTestGlobalsOnce.Do(func() {
		stats = &types.Statistics{}
		promStats = &types.PromStatistics{}
		otlpMetrics = &otlpmetrics.OTLPMetrics{}
	})
	nullClient = &outputs.Client{
		OutputType:  "null",
		Config:      config,
		Stats:       stats,
		PromStats:   promStats,
		OTLPMetrics: otlpMetrics,
	}
	initClientArgs = &types.InitClientArgs{
		Config:      config,
		Stats:       stats,
		PromStats:   promStats,
		OTLPMetrics: otlpMetrics,
	}
}

// TestReloadConfigPreservesEnvPrecedence guards the precedence order the
// reload path must keep identical to the startup one:
// env vars > config file > defaults.
func TestReloadConfigPreservesEnvPrecedence(t *testing.T) {
	writeConfigFile(t, "slack:\n  webhookurl: http://localhost/hook1\n  minimumpriority: warning\n")

	t.Setenv("SLACK_MINIMUMPRIORITY", "error")

	c, err := reloadConfig()
	require.NoError(t, err)
	require.NotNil(t, c)
	// file value applies when no env var overrides it
	require.Equal(t, "http://localhost/hook1", c.Slack.WebhookURL)
	// env var wins over the file value
	require.Equal(t, "error", c.Slack.MinimumPriority)

	// changing the file must be picked up by the next reload, env precedence unchanged
	writeConfigFile(t, "slack:\n  webhookurl: http://localhost/hook2\n")
	c, err = reloadConfig()
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, "http://localhost/hook2", c.Slack.WebhookURL)
	require.Equal(t, "error", c.Slack.MinimumPriority)
}

// TestReloadConfigFileValueUsedWithoutEnv completes the precedence check:
// without an env var, the file value wins over the default.
func TestReloadConfigFileValueUsedWithoutEnv(t *testing.T) {
	writeConfigFile(t, "webhook:\n  address: http://localhost/hook\n  minimumpriority: critical\n")

	c, err := reloadConfig()
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, "http://localhost/hook", c.Webhook.Address)
	require.Equal(t, "critical", c.Webhook.MinimumPriority)
}

// TestReloadConfigWithoutFile ensures reloadConfig is a no-op when the
// daemon was not started with -c.
func TestReloadConfigWithoutFile(t *testing.T) {
	configFilePath = ""
	c, err := reloadConfig()
	require.NoError(t, err)
	require.Nil(t, c)
}

// TestReloadConfigurationSwapsOutputs exercises a full reload cycle:
// outputs enabled in the new file are started, removed ones are dropped,
// and the global config is swapped.
func TestReloadConfigurationSwapsOutputs(t *testing.T) {
	writeConfigFile(t, "slack:\n  webhookurl: http://localhost/slack\n")
	config = mustReloadConfig(t)
	initTestGlobals()

	reloadConfiguration()
	require.Contains(t, outputs.EnabledOutputs, "Slack")
	require.NotNil(t, slackClient)
	require.Nil(t, webhookClient)

	// remove slack, add webhook: the swap must disable the first and enable the second
	writeConfigFile(t, "webhook:\n  address: http://localhost/webhook\n")
	reloadConfiguration()
	require.NotContains(t, outputs.EnabledOutputs, "Slack")
	require.Contains(t, outputs.EnabledOutputs, "Webhook")
	require.Nil(t, slackClient)
	require.NotNil(t, webhookClient)
	require.Equal(t, "http://localhost/webhook", config.Webhook.Address)
	require.Empty(t, config.Slack.WebhookURL)
}

// TestReloadConfigurationKeepsListener ensures listenaddress/listenport
// changes in the file do not affect the running listener.
func TestReloadConfigurationKeepsListener(t *testing.T) {
	writeConfigFile(t, "listenport: 2801\n")
	config = mustReloadConfig(t)
	initTestGlobals()

	writeConfigFile(t, "listenport: 9999\n")
	reloadConfiguration()
	require.Equal(t, 2801, config.ListenPort)
}

// mustReloadConfig is a test helper returning the reloaded Configuration.
func mustReloadConfig(t *testing.T) *types.Configuration {
	t.Helper()
	c, err := reloadConfig()
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

// TestReloadConfigurationAbortsOnReadError ensures a missing/unreadable
// config file aborts the reload and the running configuration and outputs
// are kept untouched.
func TestReloadConfigurationAbortsOnReadError(t *testing.T) {
	writeConfigFile(t, "slack:\n  webhookurl: http://localhost/slack\n")
	config = mustReloadConfig(t)
	initTestGlobals()

	reloadConfiguration()
	require.Contains(t, outputs.EnabledOutputs, "Slack")

	require.NoError(t, os.Remove(configFilePath))
	reloadConfiguration()
	require.Contains(t, outputs.EnabledOutputs, "Slack")
	require.NotNil(t, slackClient)
	require.Equal(t, "http://localhost/slack", config.Slack.WebhookURL)
}

// TestReloadConfigurationPreservesLabelFields ensures fields that would
// change the prometheus/OTLP label cardinality keep their startup values
// on reload (they are registered once and can not change at runtime).
func TestReloadConfigurationPreservesLabelFields(t *testing.T) {
	writeConfigFile(t, "customfields:\n  env: test\nslack:\n  webhookurl: http://localhost/slack\n")
	config = mustReloadConfig(t)
	initTestGlobals()

	writeConfigFile(t, "customfields:\n  env: prod\n  cluster: alpha\nslack:\n  webhookurl: http://localhost/slack2\n")
	reloadConfiguration()
	// label-affecting fields keep the startup values
	require.Equal(t, map[string]string{"env": "test"}, config.Customfields)
	// output fields are still reloaded
	require.Equal(t, "http://localhost/slack2", config.Slack.WebhookURL)
}

// TestReloadConfigurationPreservesTLSServer ensures tlsserver block changes
// keep the startup values on reload, like listenaddress/listenport.
func TestReloadConfigurationPreservesTLSServer(t *testing.T) {
	writeConfigFile(t, "listenport: 2801\ntlsserver:\n  notlsport: 2810\n")
	config = mustReloadConfig(t)
	initTestGlobals()

	writeConfigFile(t, "listenport: 9999\ntlsserver:\n  notlsport: 9998\n")
	reloadConfiguration()
	require.Equal(t, 2801, config.ListenPort)
	require.Equal(t, 2810, config.TLSServer.NoTLSPort)
}

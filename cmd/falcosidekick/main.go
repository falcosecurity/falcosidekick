// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/logging"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

type stringSliceFlag []string

func (f *stringSliceFlag) String() string { return strings.Join(*f, ",") }
func (f *stringSliceFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	configPath := flag.String("c", "", "core config file (sidekick.yaml)")
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.BoolVar(showVersion, "version", false, "print version and exit")
	var outputPaths stringSliceFlag
	flag.Var(&outputPaths, "o", "output config file (repeatable)")
	flag.Parse()

	if *showVersion {
		if err := writeVersion(os.Stdout, version.GetInfo()); err != nil {
			fatal(err)
		}
		return
	}

	if err := run(context.Background(), *configPath, outputPaths); err != nil {
		fatal(err)
	}
}

func writeVersion(w io.Writer, v version.Info) error {
	if _, err := fmt.Fprintf(w, "falcosidekick %s (commit: %s, built: %s, go: %s)\n",
		v.Version, v.Commit, v.BuildDate, v.GoVersion); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}

// fatal uses its own logger because slog.SetDefault redirects the log package default.
func fatal(err error) {
	log.New(os.Stderr, "", 0).Fatalf("fatal: %v", err)
}

func run(parentCtx context.Context, configPath string, outputPaths []string) error {
	appCtx, stop := signal.NotifyContext(parentCtx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Workers outlive appCtx so SIGTERM does not abort the queued-event drain.
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()

	if configPath == "" {
		slog.Warn("no config file specified (-c flag), running with defaults and environment variables only")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	outsCfg, err := config.LoadOutputs(outputPaths)
	if err != nil {
		return fmt.Errorf("outputs load: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation: %s", errs.Error())
	}

	logger, err := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	slog.SetDefault(logger)

	v := version.GetInfo()
	slog.Info("starting falcosidekick",
		"version", v.Version,
		"commit", v.Commit,
		"build_date", v.BuildDate,
		"go_version", v.GoVersion,
	)

	collector := metrics.NewCollector(cfg.Metrics)

	cat, err := catalog.New(all.Types())
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}

	app, err := NewApp(appCtx, cfg, outsCfg, collector, cat, logger)
	if err != nil {
		return err
	}

	app.pipe.Start(workerRunCtx, stopWorkers)
	app.startReloadWatchers(appCtx, workerRunCtx, outsCfg.Paths, cfg.Reload)
	if err := app.startReplicaSync(appCtx, &cfg.Database); err != nil {
		stop()
		app.shutdown()
		return fmt.Errorf("replica sync: %w", err)
	}

	serverErr := make(chan error, 1)
	app.serve(serverErr)

	select {
	case <-appCtx.Done():
	case srvErr := <-serverErr:
		slog.Error("server failed", "error", srvErr)
		stop()
		err = fmt.Errorf("server: %w", srvErr)
	}

	slog.Info("shutting down")
	app.shutdown()

	return err
}

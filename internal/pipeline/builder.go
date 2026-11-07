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

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// ErrInvalidOutputConfig matches BuildOutput failures caused by the configuration, not by driver startup.
var ErrInvalidOutputConfig = errors.New("invalid output config")

type invalidOutputConfigError struct{ cause error }

func (e invalidOutputConfigError) Error() string        { return e.cause.Error() }
func (e invalidOutputConfigError) Unwrap() error        { return e.cause }
func (e invalidOutputConfigError) Is(target error) bool { return target == ErrInvalidOutputConfig }

// BuildOutput constructs a live *Output, closing the driver on failure; the caller resolves secrets.
func BuildOutput(
	ctx context.Context,
	cat *catalog.Catalog,
	name string,
	cfg map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (*Output, error) {
	driver, err := cat.Create(name, cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("create: %w", invalidOutputConfigError{cause: err})
	}

	if err := driver.Init(ctx); err != nil {
		_ = driver.Close()
		if errors.Is(err, output.ErrMisconfigured) {
			err = invalidOutputConfigError{cause: err}
		}
		return nil, fmt.Errorf("init: %w", err)
	}

	merged, err := config.MergeRuntimeConfig(defaults, name, driver.RuntimeConfig())
	if err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("runtime merge: %w", invalidOutputConfigError{cause: err})
	}

	var healthErr error
	if merged.ProbesDestination() {
		healthCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
		healthErr = driver.HealthCheck(healthCtx)
		cancel()
	}
	if errors.Is(healthErr, output.ErrMisconfigured) {
		_ = driver.Close()
		return nil, fmt.Errorf("health check: %w", invalidOutputConfigError{cause: healthErr})
	}

	out := NewOutput(driver, &merged, deps.Metrics)
	if healthErr != nil {
		warning := "health check failed before start: " + healthErr.Error()
		out.SetHealthWarning(warning)
		if deps.Logger != nil {
			deps.Logger.Warn("output starts degraded", "output", name, "warning", warning)
		}
	}
	return out, nil
}

// BuildOutputs builds outputs concurrently; on any failure it closes them all.
func BuildOutputs(
	ctx context.Context,
	cat *catalog.Catalog,
	configs map[string]map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (map[string]*Output, error) {
	outputs, failures := BuildEach(ctx, cat, configs, defaults, deps)
	if len(failures) > 0 {
		for _, out := range outputs {
			_ = out.Close()
		}
		name := slices.Sorted(maps.Keys(failures))[0]
		return nil, fmt.Errorf("output %q: %w", name, failures[name])
	}
	return outputs, nil
}

// BuildEach builds outputs concurrently and returns those that built and the failure of each other one.
func BuildEach(
	ctx context.Context,
	cat *catalog.Catalog,
	configs map[string]map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (outputs map[string]*Output, failures map[string]error) {
	type result struct {
		out *Output
		err error
	}
	results := make(map[string]*result, len(configs))
	for name := range configs {
		results[name] = &result{}
	}
	var wg sync.WaitGroup
	for name, cfg := range configs {
		res := results[name]
		wg.Go(func() { res.out, res.err = BuildOutput(ctx, cat, name, cfg, defaults, deps) })
	}
	wg.Wait()

	outputs = make(map[string]*Output, len(results))
	failures = make(map[string]error)
	for name, res := range results {
		if res.err != nil {
			failures[name] = res.err
			continue
		}
		outputs[name] = res.out
	}
	return outputs, failures
}

const healthCheckTimeout = 5 * time.Second

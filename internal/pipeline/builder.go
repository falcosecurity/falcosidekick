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
	"log/slog"
	"maps"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// ErrInvalidOutputConfig matches BuildOutput failures caused by the configuration itself, never by the destination probe.
var ErrInvalidOutputConfig = errors.New("invalid output config")

// Phases of a refused output configuration, as the API reports them.
const (
	// PhaseValidate is a refusal by decoding, validation or the runtime merge.
	PhaseValidate = "validate"
	// PhaseBuild is a refusal by the driver's Init, which reads only local state.
	PhaseBuild = "build"
)

type invalidOutputConfigError struct {
	cause error
	phase string
}

func (e invalidOutputConfigError) Error() string        { return e.cause.Error() }
func (e invalidOutputConfigError) Unwrap() error        { return e.cause }
func (e invalidOutputConfigError) Is(target error) bool { return target == ErrInvalidOutputConfig }

// ConfigPhase returns the phase that refused err: PhaseBuild for an Init failure, PhaseValidate otherwise.
func ConfigPhase(err error) string {
	if invalid, ok := errors.AsType[invalidOutputConfigError](err); ok {
		return invalid.phase
	}
	return PhaseValidate
}

// ErrBuildPanicked replaces a driver panic during build; the panic value is logged, never returned.
var ErrBuildPanicked = errors.New("output build failed: internal error; see the falcosidekick log")

// BuildOutput constructs a live *Output, closing the driver on failure; the caller resolves secrets.
// A failed destination probe never refuses the configuration: the output starts degraded with the
// reason as its warning. A panic in the driver returns ErrBuildPanicked and leaves the driver unclosed.
func BuildOutput(
	ctx context.Context,
	cat *catalog.Catalog,
	name string,
	cfg map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (out *Output, err error) {
	defer func() {
		if p := recover(); p != nil {
			logger := deps.Logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("output build panicked", "output", name, "panic", p, "stack", string(debug.Stack()))
			out, err = nil, ErrBuildPanicked
		}
	}()
	return buildOutput(ctx, cat, name, cfg, defaults, deps)
}

func buildOutput(
	ctx context.Context,
	cat *catalog.Catalog,
	name string,
	cfg map[string]any,
	defaults output.RuntimeConfig,
	deps output.Deps,
) (*Output, error) {
	driver, err := cat.Create(name, cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("create: %w", invalidOutputConfigError{cause: err, phase: PhaseValidate})
	}

	// Merged before Init, so an invalid runtime section is refused before the driver allocates.
	merged, err := config.MergeRuntimeConfig(runtimeDefaultsFor(driver, defaults), name, driver.RuntimeConfig())
	if err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("runtime merge: %w", invalidOutputConfigError{cause: err, phase: PhaseValidate})
	}

	if err := driver.Init(ctx); err != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("init: %w", invalidOutputConfigError{cause: err, phase: PhaseBuild})
	}

	var healthErr error
	if merged.ProbesDestination() {
		healthCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
		healthErr = driver.HealthCheck(healthCtx)
		cancel()
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

// runtimeDefaultsFor turns inherited batching off for a driver that does not send batches.
func runtimeDefaultsFor(driver output.Driver, defaults output.RuntimeConfig) output.RuntimeConfig {
	if _, batches := driver.(output.BatchSender); batches || !defaults.Batching.IsEnabled() {
		return defaults
	}
	defaults = defaults.DeepCopy()
	defaults.Batching.Enabled = new(false)
	return defaults
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

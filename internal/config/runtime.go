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

package config

import (
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// MergeRuntimeConfig overlays the non-zero per-output runtime fields on the defaults.
// Zero leaves the default; a negative value is rejected rather than replaced by the default.
func MergeRuntimeConfig(defaults output.RuntimeConfig, name string, perOutput output.RuntimeConfig) (output.RuntimeConfig, error) {
	resolved := defaults.DeepCopy()
	if errs := negativeOverrides(perOutput); len(errs) > 0 {
		return resolved, fmt.Errorf("output %q: %s", name, errs.Error())
	}

	if perOutput.QueueSize > 0 {
		resolved.QueueSize = perOutput.QueueSize
	}
	if perOutput.Workers > 0 {
		resolved.Workers = perOutput.Workers
	}
	if perOutput.MinPriority != "" {
		resolved.MinPriority = perOutput.MinPriority
	}
	// The filter compares canonical priorities; the configuration accepts any case.
	if resolved.MinPriority != "" {
		priority, err := event.ParsePriority(string(resolved.MinPriority))
		if err != nil {
			return resolved, fmt.Errorf("output %q: minimum_priority: must be a Falco priority", name)
		}
		resolved.MinPriority = priority
	}
	if perOutput.Retry != nil {
		merged := *resolved.Retry
		if perOutput.Retry.MaxAttempts > 0 {
			merged.MaxAttempts = perOutput.Retry.MaxAttempts
		}
		if perOutput.Retry.InitialInterval > 0 {
			merged.InitialInterval = perOutput.Retry.InitialInterval
		}
		if perOutput.Retry.MaxInterval > 0 {
			merged.MaxInterval = perOutput.Retry.MaxInterval
		}
		if perOutput.Retry.Multiplier > 0 {
			merged.Multiplier = perOutput.Retry.Multiplier
		}
		resolved.Retry = &merged
	}
	if perOutput.CircuitBreaker != nil {
		merged := *resolved.CircuitBreaker
		if perOutput.CircuitBreaker.FailureThreshold > 0 {
			merged.FailureThreshold = perOutput.CircuitBreaker.FailureThreshold
		}
		if perOutput.CircuitBreaker.SuccessThreshold > 0 {
			merged.SuccessThreshold = perOutput.CircuitBreaker.SuccessThreshold
		}
		if perOutput.CircuitBreaker.ResetTimeout > 0 {
			merged.ResetTimeout = perOutput.CircuitBreaker.ResetTimeout
		}
		resolved.CircuitBreaker = &merged
	}
	if perOutput.Batching != nil {
		merged := output.BatchingConfig{
			Enabled:       perOutput.Batching.Enabled,
			BatchSize:     resolved.Batching.BatchSize,
			FlushInterval: resolved.Batching.FlushInterval,
		}
		if perOutput.Batching.BatchSize > 0 {
			merged.BatchSize = perOutput.Batching.BatchSize
		}
		if perOutput.Batching.FlushInterval > 0 {
			merged.FlushInterval = perOutput.Batching.FlushInterval
		}
		resolved.Batching = &merged
	}
	if perOutput.HealthCheck != nil {
		enabled := *perOutput.HealthCheck
		resolved.HealthCheck = &enabled
	}

	if errs := resolved.Validate(); len(errs) > 0 {
		return resolved, fmt.Errorf("output %q: %s", name, errs.Error())
	}

	return resolved, nil
}

// negativeOverrides reports the per-output fields set below zero.
func negativeOverrides(c output.RuntimeConfig) utils.ValidationErrors {
	var errs utils.ValidationErrors
	check := func(field string, negative bool) {
		if negative {
			errs.Add("runtime."+field, "must not be negative")
		}
	}
	check("queue_size", c.QueueSize < 0)
	check("workers", c.Workers < 0)
	if r := c.Retry; r != nil {
		check("retry.max_attempts", r.MaxAttempts < 0)
		check("retry.initial_interval", r.InitialInterval < 0)
		check("retry.max_interval", r.MaxInterval < 0)
		check("retry.multiplier", r.Multiplier < 0)
	}
	if cb := c.CircuitBreaker; cb != nil {
		check("circuit_breaker.failure_threshold", cb.FailureThreshold < 0)
		check("circuit_breaker.success_threshold", cb.SuccessThreshold < 0)
		check("circuit_breaker.reset_timeout", cb.ResetTimeout < 0)
	}
	if b := c.Batching; b != nil {
		check("batching.batch_size", b.BatchSize < 0)
		check("batching.flush_interval", b.FlushInterval < 0)
	}
	return errs
}

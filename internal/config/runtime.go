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
)

// MergeRuntimeConfig merges per-output runtime overrides into runtime defaults.
// Zero-value fields in perOutput keep the default. Non-zero fields override.
func MergeRuntimeConfig(defaults output.RuntimeConfig, name string, perOutput output.RuntimeConfig) (output.RuntimeConfig, error) {
	resolved := defaults.DeepCopy()

	if perOutput.QueueSize > 0 {
		resolved.QueueSize = perOutput.QueueSize
	}
	if perOutput.Workers > 0 {
		resolved.Workers = perOutput.Workers
	}
	if perOutput.MinPriority != "" {
		if _, err := event.ParsePriority(string(perOutput.MinPriority)); err != nil {
			return resolved, fmt.Errorf("output %q: %w", name, err)
		}
		resolved.MinPriority = perOutput.MinPriority
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

	if errs := resolved.Validate(); len(errs) > 0 {
		return resolved, fmt.Errorf("output %q: %s", name, errs.Error())
	}

	return resolved, nil
}

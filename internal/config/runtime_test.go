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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestValidateDelegatesRetry(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Retry.MaxAttempts = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if assert.ObjectsAreEqual("retry.max_attempts", e.Field) || assert.ObjectsAreEqual("runtime_defaults.retry.max_attempts", e.Field) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected error about retry.max_attempts, got: %v", errs)
}

func TestValidateDelegatesCircuitBreaker(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.CircuitBreaker.FailureThreshold = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if assert.ObjectsAreEqual("circuit_breaker.failure_threshold", e.Field) || assert.ObjectsAreEqual("runtime_defaults.circuit_breaker.failure_threshold", e.Field) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected error about circuit_breaker.failure_threshold, got: %v", errs)
}

func TestValidateEnricherThresholds(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Enricher.TruncateEventThreshold = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestMergeRuntimeConfigDefaults(t *testing.T) {
	cfg := loadDefaults(t)
	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "nonexistent", output.RuntimeConfig{})

	assert.Equal(t, cfg.RuntimeDefaults.QueueSize, resolved.QueueSize)
	assert.Equal(t, cfg.RuntimeDefaults.Workers, resolved.Workers)
}

func TestMergeRuntimeConfigZeroOverrideKeepsDefault(t *testing.T) {
	cfg := loadDefaults(t)

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", output.RuntimeConfig{})
	assert.Equal(t, cfg.RuntimeDefaults.QueueSize, resolved.QueueSize, "zero override returns runtime defaults")
}

func TestMergeRuntimeConfigOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		QueueSize:   5000,
		Workers:     4,
		MinPriority: event.PriorityWarning,
	}

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "es", perOutput)
	assert.Equal(t, 5000, resolved.QueueSize)
	assert.Equal(t, 4, resolved.Workers)
	assert.Equal(t, event.PriorityWarning, resolved.MinPriority)
}

func TestMergeRuntimeConfigBatchingOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:   true,
			BatchSize: 1000,
		},
	}

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "es", perOutput)
	assert.True(t, resolved.Batching.Enabled)
	assert.Equal(t, 1000, resolved.Batching.BatchSize)
}

func TestMergeRuntimeConfigBatchingFlushInterval(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:       true,
			FlushInterval: 5 * time.Second,
		},
	}

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "loki", perOutput)
	assert.Equal(t, 5*time.Second, resolved.Batching.FlushInterval)
}

func TestMergeRuntimeConfigIgnoresZeroValues(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{}

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "test", perOutput)
	assert.Equal(t, cfg.RuntimeDefaults.QueueSize, resolved.QueueSize, "zero value must not override")
	assert.Equal(t, cfg.RuntimeDefaults.Workers, resolved.Workers, "zero value must not override")
}

func TestMergeRuntimeConfigInvalidPriority(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		MinPriority: event.Priority("invalid_priority"),
	}

	_, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook")
}

func TestMergeRuntimeConfigInvalidBatchingOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     0,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled: true,
		},
	}

	_, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch_size")
}

func TestValidateDelegatesBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{Enabled: true, BatchSize: -1}

	errs := cfg.Validate()
	require.NotEmpty(t, errs)
}

func TestMergeRuntimeConfigRetryOverride(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Retry: &output.RetryConfig{
			MaxAttempts:     5,
			InitialInterval: 2 * time.Second,
			MaxInterval:     60 * time.Second,
			Multiplier:      3.0,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.Equal(t, 5, resolved.Retry.MaxAttempts)
	assert.Equal(t, 2*time.Second, resolved.Retry.InitialInterval)
	assert.Equal(t, 60*time.Second, resolved.Retry.MaxInterval)
	assert.Equal(t, 3.0, resolved.Retry.Multiplier)
}

func TestMergeRuntimeConfigCircuitBreakerOverride(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 10,
			SuccessThreshold: 3,
			ResetTimeout:     60 * time.Second,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.Equal(t, 10, resolved.CircuitBreaker.FailureThreshold)
	assert.Equal(t, 3, resolved.CircuitBreaker.SuccessThreshold)
	assert.Equal(t, 60*time.Second, resolved.CircuitBreaker.ResetTimeout)
}

func TestMergeRuntimeConfigDisableBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled: false,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.False(t, resolved.Batching.Enabled, "per-output batching.enabled=false must override runtime default")
}

func TestMergeRuntimeConfigPartialRetryOverride(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Retry: &output.RetryConfig{
			MaxAttempts: 10,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.Equal(t, 10, resolved.Retry.MaxAttempts, "overridden field must change")
	assert.Equal(t, cfg.RuntimeDefaults.Retry.InitialInterval, resolved.Retry.InitialInterval, "non-overridden field must keep default")
	assert.Equal(t, cfg.RuntimeDefaults.Retry.MaxInterval, resolved.Retry.MaxInterval, "non-overridden field must keep default")
	assert.Equal(t, cfg.RuntimeDefaults.Retry.Multiplier, resolved.Retry.Multiplier, "non-overridden field must keep default")
}

func TestMergeRuntimeConfigPartialCircuitBreakerOverride(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 20,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.Equal(t, 20, resolved.CircuitBreaker.FailureThreshold, "overridden field must change")
	assert.Equal(t, cfg.RuntimeDefaults.CircuitBreaker.SuccessThreshold, resolved.CircuitBreaker.SuccessThreshold, "non-overridden field must keep default")
	assert.Equal(t, cfg.RuntimeDefaults.CircuitBreaker.ResetTimeout, resolved.CircuitBreaker.ResetTimeout, "non-overridden field must keep default")
}

func TestMergeRuntimeConfigPartialBatchingOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:   true,
			BatchSize: 2000,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	require.NotNil(t, resolved.Batching)
	assert.Equal(t, 2000, resolved.Batching.BatchSize, "overridden field must change")
	assert.True(t, resolved.Batching.Enabled, "enabled must be preserved when explicitly set")
	assert.Equal(t, time.Second, resolved.Batching.FlushInterval, "non-overridden flush_interval must keep default")
}

func TestMergeRuntimeConfigDoesNotMutateDefaults(t *testing.T) {
	cfg := loadDefaults(t)
	originalMaxAttempts := cfg.RuntimeDefaults.Retry.MaxAttempts
	perOutput := output.RuntimeConfig{
		Retry: &output.RetryConfig{
			MaxAttempts: 99,
		},
	}

	_, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.Equal(t, originalMaxAttempts, cfg.RuntimeDefaults.Retry.MaxAttempts, "runtime defaults must not be mutated by merge")
}

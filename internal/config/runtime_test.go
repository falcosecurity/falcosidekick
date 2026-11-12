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
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
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

func TestMergeRuntimeConfigHealthCheck(t *testing.T) {
	off, on := false, true
	tests := []struct {
		defaults, perOutput *bool
		name                string
		want                bool
	}{
		{name: "probes by default", want: true},
		{name: "disabled for one output", perOutput: &off, want: false},
		{name: "disabled for all", defaults: &off, want: false},
		{name: "disabled for all, enabled for one", defaults: &off, perOutput: &on, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaults := loadDefaults(t).RuntimeDefaults
			defaults.HealthCheck = tt.defaults
			resolved, err := MergeRuntimeConfig(defaults, "loki", output.RuntimeConfig{HealthCheck: tt.perOutput})
			require.NoError(t, err)
			assert.Equal(t, tt.want, resolved.ProbesDestination())
		})
	}
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

func TestMergeRuntimeConfigNormalizesPriority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		defaults  event.Priority
		perOutput event.Priority
	}{
		{name: "per output", perOutput: "WARNING"},
		{name: "defaults", defaults: " Warning "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadDefaults(t)
			cfg.RuntimeDefaults.MinPriority = tc.defaults
			resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", output.RuntimeConfig{MinPriority: tc.perOutput})
			require.NoError(t, err)
			assert.Equal(t, event.PriorityWarning, resolved.MinPriority)
		})
	}
}

func TestMergeRuntimeConfigRejectsOverridesOutOfRange(t *testing.T) {
	cfg := loadDefaults(t)
	retry := func(r output.RetryConfig) output.RuntimeConfig { return output.RuntimeConfig{Retry: &r} }
	breaker := func(cb output.CircuitBreakerConfig) output.RuntimeConfig {
		return output.RuntimeConfig{CircuitBreaker: &cb}
	}
	batching := func(b output.BatchingConfig) output.RuntimeConfig { return output.RuntimeConfig{Batching: &b} }
	for _, tc := range []struct {
		name      string
		want      string // empty: accepted
		perOutput output.RuntimeConfig
	}{
		// A typed value below 1 is an omitted one; the schema refuses it in the raw config.
		{name: "queue size negative keeps the default", perOutput: output.RuntimeConfig{QueueSize: -1}},
		{name: "queue size min", perOutput: output.RuntimeConfig{QueueSize: 1}},
		{name: "queue size max", perOutput: output.RuntimeConfig{QueueSize: 100_000}},
		{name: "queue size above max", perOutput: output.RuntimeConfig{QueueSize: 100_001}, want: "runtime.queue_size: must be an integer between 1 and 100000"},
		{name: "workers max", perOutput: output.RuntimeConfig{Workers: 256}},
		{name: "workers above max", perOutput: output.RuntimeConfig{Workers: 257}, want: "runtime.workers: must be an integer between 1 and 256"},
		{name: "attempts above max", perOutput: retry(output.RetryConfig{MaxAttempts: 101}), want: "runtime.retry.max_attempts: must be an integer between 1 and 100"},
		{name: "attempts max", perOutput: retry(output.RetryConfig{MaxAttempts: 100})},
		{name: "interval above max", perOutput: retry(output.RetryConfig{MaxInterval: time.Hour + 1}), want: "runtime.retry.max_interval: must be a duration between 1ms and 1h"},
		{name: "multiplier below min", perOutput: retry(output.RetryConfig{Multiplier: 0.5}), want: "runtime.retry.multiplier: must be a number between 1 and 10"},
		{name: "multiplier above max", perOutput: retry(output.RetryConfig{Multiplier: 10.5}), want: "runtime.retry.multiplier: must be a number between 1 and 10"},
		{name: "threshold above max", perOutput: breaker(output.CircuitBreakerConfig{FailureThreshold: 10_001}),
			want: "runtime.circuit_breaker.failure_threshold: must be an integer between 1 and 10000"},
		{name: "reset timeout above max", perOutput: breaker(output.CircuitBreakerConfig{ResetTimeout: time.Hour + time.Second}),
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "batch size above max", perOutput: batching(output.BatchingConfig{Enabled: new(true), BatchSize: 10_001}),
			want: "runtime.batching.batch_size: must be an integer between 1 and 10000"},
		{name: "flush interval below min", perOutput: batching(output.BatchingConfig{FlushInterval: time.Millisecond}),
			want: "runtime.batching.flush_interval: must be a duration between 10ms and 1h"},
		{name: "batched events at the limit", perOutput: output.RuntimeConfig{Workers: 10, Batching: &output.BatchingConfig{Enabled: new(true), BatchSize: 10_000}}},
		{name: "batched events above the limit", perOutput: output.RuntimeConfig{Workers: 11, Batching: &output.BatchingConfig{Enabled: new(true), BatchSize: 10_000}},
			want: "runtime.batching.batch_size: must be at most 9090 with 11 workers: workers × batch_size is limited to 100000"},
		{name: "batched events ignored while batching is off", perOutput: output.RuntimeConfig{Workers: 256, Batching: &output.BatchingConfig{BatchSize: 10_000}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", tc.perOutput)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, `output "webhook": `+tc.want, "a value out of range is a mistake, not a request for the default")
		})
	}
}

func TestMergeRuntimeConfigBatchingOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:   new(true),
			BatchSize: 1000,
		},
	}

	resolved, _ := MergeRuntimeConfig(cfg.RuntimeDefaults, "es", perOutput)
	assert.True(t, resolved.Batching.IsEnabled())
	assert.Equal(t, 1000, resolved.Batching.BatchSize)
}

func TestMergeRuntimeConfigBatchingFlushInterval(t *testing.T) {
	cfg := loadDefaults(t)
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:       new(true),
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
		Enabled:       new(true),
		BatchSize:     0,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled: new(true),
		},
	}

	_, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch_size")
}

func TestValidateDelegatesBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: -1}

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

func TestMergeRuntimeConfigBatchingEnabledPresence(t *testing.T) {
	cfg := loadDefaults(t)
	for _, tc := range []struct {
		inherited *bool
		set       *bool
		name      string
		want      bool
	}{
		{name: "omitted inherits true", inherited: new(true), want: true},
		{name: "omitted inherits false", inherited: new(false), want: false},
		{name: "explicit false disables", inherited: new(true), set: new(false), want: false},
		{name: "explicit true enables", inherited: new(false), set: new(true), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defaults := cfg.RuntimeDefaults.DeepCopy()
			defaults.Batching.Enabled = tc.inherited
			perOutput := output.RuntimeConfig{Batching: &output.BatchingConfig{Enabled: tc.set, BatchSize: 100}}
			resolved, err := MergeRuntimeConfig(defaults, "webhook", perOutput)
			require.NoError(t, err)
			assert.Equal(t, tc.want, resolved.Batching.IsEnabled())
			assert.Equal(t, 100, resolved.Batching.BatchSize)
			assert.Equal(t, defaults.Batching.FlushInterval, resolved.Batching.FlushInterval)
			assert.Equal(t, tc.inherited, defaults.Batching.Enabled, "the defaults are not changed")
		})
	}
}

func TestMergeRuntimeConfigBatchingWithoutDefaults(t *testing.T) {
	cfg := loadDefaults(t)
	defaults := cfg.RuntimeDefaults.DeepCopy()
	defaults.Batching = nil
	resolved, err := MergeRuntimeConfig(defaults, "webhook", output.RuntimeConfig{
		Batching: &output.BatchingConfig{Enabled: new(true), BatchSize: 10, FlushInterval: time.Second},
	})
	require.NoError(t, err)
	assert.True(t, resolved.Batching.IsEnabled())
}

func TestBatchingEnabledDecodesPresence(t *testing.T) {
	for _, tc := range []struct {
		raw  map[string]any
		want *bool
		name string
	}{
		{name: "absent", raw: map[string]any{"batch_size": 10}},
		{name: "null", raw: map[string]any{"enabled": nil}},
		{name: "false", raw: map[string]any{"enabled": false}, want: new(false)},
		{name: "true", raw: map[string]any{"enabled": true}, want: new(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target struct {
				Runtime output.RuntimeConfig `mapstructure:"runtime"`
			}
			require.NoError(t, shared.DecodeDriverConfig(map[string]any{"runtime": map[string]any{"batching": tc.raw}}, &target))
			assert.Equal(t, tc.want, target.Runtime.Batching.Enabled)
		})
	}
}

func TestMergeRuntimeConfigDisableBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.RuntimeDefaults.Batching = &output.BatchingConfig{
		Enabled:       new(true),
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled: new(false),
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	assert.False(t, resolved.Batching.IsEnabled(), "per-output batching.enabled=false must override runtime default")
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
		Enabled:       new(true),
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	perOutput := output.RuntimeConfig{
		Batching: &output.BatchingConfig{
			Enabled:   new(true),
			BatchSize: 2000,
		},
	}

	resolved, err := MergeRuntimeConfig(cfg.RuntimeDefaults, "webhook", perOutput)
	require.NoError(t, err)
	require.NotNil(t, resolved.Batching)
	assert.Equal(t, 2000, resolved.Batching.BatchSize, "overridden field must change")
	assert.True(t, resolved.Batching.IsEnabled(), "enabled must be preserved when explicitly set")
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

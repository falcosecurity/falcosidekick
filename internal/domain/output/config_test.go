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

package output

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func validConfig() RuntimeConfig {
	return RuntimeConfig{
		QueueSize: 1000,
		Workers:   2,
		Retry: &RetryConfig{
			MaxAttempts:     3,
			InitialInterval: time.Second,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
		},
		CircuitBreaker: &CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func TestConfigValidateValid(t *testing.T) {
	cfg := validConfig()
	assert.Empty(t, cfg.Validate())
}

func TestConfigValidateZeroValues(t *testing.T) {
	assert.NotEmpty(t, (&RuntimeConfig{}).Validate())
}

func TestConfigValidateNegativeQueueSize(t *testing.T) {
	cfg := validConfig()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestRetryConfigValidateValid(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:     3,
		InitialInterval: time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}
	assert.Empty(t, cfg.Validate())
}

func TestRetryConfigValidateZeroValues(t *testing.T) {
	assert.NotEmpty(t, (&RetryConfig{}).Validate())
}

func TestRetryConfigValidateNegative(t *testing.T) {
	cfg := &RetryConfig{MaxAttempts: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRetryConfigValidatePartialInvalid(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:     3,
		InitialInterval: time.Second,
		MaxInterval:     0,
		Multiplier:      2.0,
	}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
	assert.Len(t, errs, 1)
}

func TestComputeBackoffExponential(t *testing.T) {
	cfg := &RetryConfig{
		InitialInterval: time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 30 * time.Second},
		{7, 30 * time.Second},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, cfg.ComputeBackoff(tt.attempt), "attempt %d", tt.attempt)
	}
}

func TestComputeBackoffCapsAtMax(t *testing.T) {
	cfg := &RetryConfig{
		InitialInterval: 10 * time.Second,
		MaxInterval:     15 * time.Second,
		Multiplier:      2.0,
	}
	assert.Equal(t, 10*time.Second, cfg.ComputeBackoff(1))
	assert.Equal(t, 15*time.Second, cfg.ComputeBackoff(2))
	assert.Equal(t, 15*time.Second, cfg.ComputeBackoff(10))
}

func TestCircuitBreakerConfigValidateValid(t *testing.T) {
	cfg := &CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		ResetTimeout:     30 * time.Second,
	}
	assert.Empty(t, cfg.Validate())
}

func TestCircuitBreakerConfigValidateZeroValues(t *testing.T) {
	assert.NotEmpty(t, (&CircuitBreakerConfig{}).Validate())
}

func TestCircuitBreakerConfigValidateNegative(t *testing.T) {
	cfg := &CircuitBreakerConfig{FailureThreshold: -1, SuccessThreshold: 2, ResetTimeout: 30 * time.Second}
	assert.NotEmpty(t, cfg.Validate())
}

func TestBatchingConfigValidation(t *testing.T) {
	tests := []struct {
		cfg     *BatchingConfig
		name    string
		wantErr bool
	}{
		{name: "disabled is validated too", cfg: &BatchingConfig{Enabled: new(false)}, wantErr: true},
		{name: "disabled valid", cfg: &BatchingConfig{Enabled: new(false), BatchSize: 100, FlushInterval: time.Second}, wantErr: false},
		{name: "valid enabled", cfg: &BatchingConfig{Enabled: new(true), BatchSize: 100, FlushInterval: time.Second}, wantErr: false},
		{name: "zero batch size", cfg: &BatchingConfig{Enabled: new(true), BatchSize: 0, FlushInterval: time.Second}, wantErr: true},
		{name: "negative batch size", cfg: &BatchingConfig{Enabled: new(true), BatchSize: -1, FlushInterval: time.Second}, wantErr: true},
		{name: "zero flush interval", cfg: &BatchingConfig{Enabled: new(true), BatchSize: 100, FlushInterval: 0}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestRuntimeConfigBounds(t *testing.T) {
	batching := func(c *RuntimeConfig, enabled bool, size int) {
		c.Batching = &BatchingConfig{Enabled: &enabled, BatchSize: size, FlushInterval: time.Second}
	}
	tests := []struct {
		mutate func(*RuntimeConfig)
		name   string
		want   string // empty: valid
	}{
		{name: "workers below min", mutate: func(c *RuntimeConfig) { c.Workers = 0 }, want: "workers: must be an integer between 1 and 256"},
		{name: "workers min", mutate: func(c *RuntimeConfig) { c.Workers = 1 }},
		{name: "workers max", mutate: func(c *RuntimeConfig) { c.Workers = 256 }},
		{name: "workers above max", mutate: func(c *RuntimeConfig) { c.Workers = 257 }, want: "workers: must be an integer between 1 and 256"},
		{name: "queue below min", mutate: func(c *RuntimeConfig) { c.QueueSize = 0 }, want: "queue_size: must be an integer between 1 and 100000"},
		{name: "queue min", mutate: func(c *RuntimeConfig) { c.QueueSize = 1 }},
		{name: "queue max", mutate: func(c *RuntimeConfig) { c.QueueSize = 100_000 }},
		{name: "queue above max", mutate: func(c *RuntimeConfig) { c.QueueSize = 100_001 }, want: "queue_size: must be an integer between 1 and 100000"},
		{name: "attempts below min", mutate: func(c *RuntimeConfig) { c.Retry.MaxAttempts = 0 }, want: "retry.max_attempts: must be an integer between 1 and 100"},
		{name: "attempts min", mutate: func(c *RuntimeConfig) { c.Retry.MaxAttempts = 1 }},
		{name: "attempts max", mutate: func(c *RuntimeConfig) { c.Retry.MaxAttempts = 100 }},
		{name: "attempts above max", mutate: func(c *RuntimeConfig) { c.Retry.MaxAttempts = 101 }, want: "retry.max_attempts: must be an integer between 1 and 100"},
		{name: "multiplier below min", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = 0.99 }, want: "retry.multiplier: must be a number between 1 and 10"},
		{name: "multiplier min", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = 1 }},
		{name: "multiplier max", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = 10 }},
		{name: "multiplier above max", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = 10.01 }, want: "retry.multiplier: must be a number between 1 and 10"},
		{name: "multiplier NaN", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = math.NaN() }, want: "retry.multiplier: must be a number between 1 and 10"},
		{name: "multiplier infinite", mutate: func(c *RuntimeConfig) { c.Retry.Multiplier = math.Inf(1) }, want: "retry.multiplier: must be a number between 1 and 10"},
		{name: "initial interval below min", mutate: func(c *RuntimeConfig) { c.Retry.InitialInterval = time.Millisecond - 1 }, want: "retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "initial interval min", mutate: func(c *RuntimeConfig) { c.Retry.InitialInterval = time.Millisecond }},
		{name: "max interval max", mutate: func(c *RuntimeConfig) { c.Retry.MaxInterval = time.Hour }},
		{name: "max interval above max", mutate: func(c *RuntimeConfig) { c.Retry.MaxInterval = time.Hour + 1 }, want: "retry.max_interval: must be a duration between 1ms and 1h"},
		{name: "failure threshold below min", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.FailureThreshold = 0 }, want: "circuit_breaker.failure_threshold: must be an integer between 1 and 10000"},
		{name: "failure threshold max", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.FailureThreshold = 10_000 }},
		{name: "success threshold above max", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.SuccessThreshold = 10_001 }, want: "circuit_breaker.success_threshold: must be an integer between 1 and 10000"},
		{name: "success threshold min", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.SuccessThreshold = 1 }},
		{name: "reset timeout below min", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.ResetTimeout = time.Second - 1 }, want: "circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "reset timeout max", mutate: func(c *RuntimeConfig) { c.CircuitBreaker.ResetTimeout = time.Hour }},
		{name: "batch size below min", mutate: func(c *RuntimeConfig) { batching(c, true, 0) }, want: "batching.batch_size: must be an integer between 1 and 10000"},
		{name: "batch size below min while disabled", mutate: func(c *RuntimeConfig) { batching(c, false, 0) }, want: "batching.batch_size: must be an integer between 1 and 10000"},
		{name: "batch size min", mutate: func(c *RuntimeConfig) { batching(c, true, 1) }},
		{name: "batch size max", mutate: func(c *RuntimeConfig) { batching(c, true, 10_000) }},
		{name: "batch size above max", mutate: func(c *RuntimeConfig) { batching(c, true, 10_001) }, want: "batching.batch_size: must be an integer between 1 and 10000"},
		{name: "flush interval below min", mutate: func(c *RuntimeConfig) { batching(c, true, 1); c.Batching.FlushInterval = 9 * time.Millisecond },
			want: "batching.flush_interval: must be a duration between 10ms and 1h"},
		{name: "batched events at the limit", mutate: func(c *RuntimeConfig) { c.Workers = 250; batching(c, true, 400) }},
		{name: "batched events above the limit", mutate: func(c *RuntimeConfig) { c.Workers = 250; batching(c, true, 401) },
			want: "batching.batch_size: must be at most 400 with 250 workers: workers × batch_size is limited to 100000"},
		{name: "batched events at both maxima", mutate: func(c *RuntimeConfig) { c.Workers = 256; batching(c, true, 10_000) },
			want: "batching.batch_size: must be at most 390 with 256 workers: workers × batch_size is limited to 100000"},
		{name: "batched events while batching is off", mutate: func(c *RuntimeConfig) { c.Workers = 256; batching(c, false, 10_000) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			errs := cfg.Validate()
			if tt.want == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Equal(t, tt.want, errs.Error())
		})
	}
}

// An overflowing float converts to MaxInt64 on arm64 and MinInt64 on amd64, which would make the wait negative.
func TestComputeBackoffNeverOverflows(t *testing.T) {
	for _, tt := range []struct {
		name       string
		multiplier float64
		attempt    int
	}{
		{name: "largest allowed", multiplier: 10, attempt: 100},
		{name: "beyond int64 nanoseconds", multiplier: 1e6, attempt: 10},
		{name: "infinite product", multiplier: 1e300, attempt: 3},
		{name: "NaN multiplier", multiplier: math.NaN(), attempt: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := RetryConfig{InitialInterval: time.Second, MaxInterval: 30 * time.Second, Multiplier: tt.multiplier}
			assert.Equal(t, 30*time.Second, cfg.ComputeBackoff(tt.attempt))
		})
	}
}

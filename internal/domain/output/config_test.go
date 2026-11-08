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
		{name: "disabled skips validation", cfg: &BatchingConfig{Enabled: false}, wantErr: false},
		{name: "valid enabled", cfg: &BatchingConfig{Enabled: true, BatchSize: 100, FlushInterval: time.Second}, wantErr: false},
		{name: "zero batch size", cfg: &BatchingConfig{Enabled: true, BatchSize: 0, FlushInterval: time.Second}, wantErr: true},
		{name: "negative batch size", cfg: &BatchingConfig{Enabled: true, BatchSize: -1, FlushInterval: time.Second}, wantErr: true},
		{name: "zero flush interval", cfg: &BatchingConfig{Enabled: true, BatchSize: 100, FlushInterval: 0}, wantErr: true},
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

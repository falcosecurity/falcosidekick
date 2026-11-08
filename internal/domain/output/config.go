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
	"fmt"
	"math"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// RuntimeConfig holds runtime output configuration settings.
// Pointer fields are nil when not specified (used for per-output overrides).
type RuntimeConfig struct {
	Retry          *RetryConfig          `json:"retry,omitempty" mapstructure:"retry"`
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty" mapstructure:"circuit_breaker"`
	Batching       *BatchingConfig       `json:"batching,omitempty" mapstructure:"batching"`
	MinPriority    event.Priority        `json:"minimum_priority" mapstructure:"minimum_priority"`
	QueueSize      int                   `json:"queue_size" mapstructure:"queue_size"`
	Workers        int                   `json:"workers" mapstructure:"workers"`
}

// Validate checks runtime config for errors.
func (c *RuntimeConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if c.QueueSize <= 0 {
		errs.Add("queue_size", fmt.Sprintf("must be positive, got %d", c.QueueSize))
	}
	if c.Workers <= 0 {
		errs.Add("workers", fmt.Sprintf("must be positive, got %d", c.Workers))
	}
	if c.MinPriority != "" {
		if _, err := event.ParsePriority(string(c.MinPriority)); err != nil {
			errs.Add("minimum_priority", fmt.Sprintf("invalid priority %q", c.MinPriority))
		}
	}
	if c.Retry == nil {
		errs.Add("retry", "is required")
	} else {
		errs.Merge("retry", c.Retry.Validate())
	}
	if c.CircuitBreaker == nil {
		errs.Add("circuit_breaker", "is required")
	} else {
		errs.Merge("circuit_breaker", c.CircuitBreaker.Validate())
	}
	if c.Batching != nil {
		errs.Merge("batching", c.Batching.Validate())
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// DeepCopy creates a deep copy of the config.
func (c *RuntimeConfig) DeepCopy() RuntimeConfig {
	cp := *c
	if c.Retry != nil {
		r := *c.Retry
		cp.Retry = &r
	}
	if c.CircuitBreaker != nil {
		cb := *c.CircuitBreaker
		cp.CircuitBreaker = &cb
	}
	if c.Batching != nil {
		b := *c.Batching
		cp.Batching = &b
	}
	return cp
}

// RetryConfig holds retry policy settings.
type RetryConfig struct {
	InitialInterval time.Duration `json:"initial_interval" mapstructure:"initial_interval"`
	MaxInterval     time.Duration `json:"max_interval" mapstructure:"max_interval"`
	MaxAttempts     int           `json:"max_attempts" mapstructure:"max_attempts"`
	Multiplier      float64       `json:"multiplier" mapstructure:"multiplier"`
}

// Validate checks retry settings for errors.
func (r *RetryConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if r.MaxAttempts <= 0 {
		errs.Add("max_attempts", fmt.Sprintf("must be > 0, got %d", r.MaxAttempts))
	}
	if r.InitialInterval <= 0 {
		errs.Add("initial_interval", fmt.Sprintf("must be > 0, got %v", r.InitialInterval))
	}
	if r.MaxInterval <= 0 {
		errs.Add("max_interval", fmt.Sprintf("must be > 0, got %v", r.MaxInterval))
	}
	if r.Multiplier <= 0 {
		errs.Add("multiplier", fmt.Sprintf("must be > 0, got %f", r.Multiplier))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ComputeBackoff returns the wait duration for the given attempt number.
func (r *RetryConfig) ComputeBackoff(attempt int) time.Duration {
	interval := float64(r.InitialInterval) * math.Pow(r.Multiplier, float64(attempt-1))
	if time.Duration(interval) > r.MaxInterval {
		return r.MaxInterval
	}
	return time.Duration(interval)
}

// CircuitBreakerConfig holds circuit breaker thresholds.
type CircuitBreakerConfig struct {
	ResetTimeout     time.Duration `json:"reset_timeout" mapstructure:"reset_timeout"`
	FailureThreshold int           `json:"failure_threshold" mapstructure:"failure_threshold"`
	SuccessThreshold int           `json:"success_threshold" mapstructure:"success_threshold"`
}

// Validate checks circuit breaker settings for errors.
func (c *CircuitBreakerConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.FailureThreshold <= 0 {
		errs.Add("failure_threshold", fmt.Sprintf("must be > 0, got %d", c.FailureThreshold))
	}
	if c.SuccessThreshold <= 0 {
		errs.Add("success_threshold", fmt.Sprintf("must be > 0, got %d", c.SuccessThreshold))
	}
	if c.ResetTimeout <= 0 {
		errs.Add("reset_timeout", fmt.Sprintf("must be > 0, got %v", c.ResetTimeout))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// BatchingConfig holds per-output batching settings.
type BatchingConfig struct {
	FlushInterval time.Duration `json:"flush_interval" mapstructure:"flush_interval"`
	BatchSize     int           `json:"batch_size" mapstructure:"batch_size"`
	Enabled       bool          `json:"enabled" mapstructure:"enabled"`
}

// Validate checks batching settings for errors.
func (c *BatchingConfig) Validate() utils.ValidationErrors {
	if !c.Enabled {
		return nil
	}
	var errs utils.ValidationErrors
	if c.BatchSize <= 0 {
		errs.Add("batch_size", fmt.Sprintf("must be positive when enabled, got %d", c.BatchSize))
	}
	if c.FlushInterval <= 0 {
		errs.Add("flush_interval", fmt.Sprintf("must be positive when enabled, got %s", c.FlushInterval))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

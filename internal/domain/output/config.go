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

// Runtime bounds, shared by validation and the output schema.
var (
	WorkersRange       = utils.IntRange{Min: 1, Max: 256}
	QueueSizeRange     = utils.IntRange{Min: 1, Max: 100_000}
	BatchSizeRange     = utils.IntRange{Min: 1, Max: 10_000}
	MaxAttemptsRange   = utils.IntRange{Min: 1, Max: 100}
	ThresholdRange     = utils.IntRange{Min: 1, Max: 10_000}
	MultiplierRange    = utils.FloatRange{Min: 1, Max: 10}
	IntervalRange      = utils.DurationRange{Min: time.Millisecond, Max: time.Hour}
	ResetTimeoutRange  = utils.DurationRange{Min: time.Second, Max: time.Hour}
	FlushIntervalRange = utils.DurationRange{Min: 10 * time.Millisecond, Max: time.Hour}
)

// MaxBatchedEvents bounds workers × batch_size, the events the batch workers of one output hold.
const MaxBatchedEvents = 100_000

// RuntimeConfig holds runtime output settings; a nil field means not overridden.
type RuntimeConfig struct {
	Retry          *RetryConfig          `json:"retry,omitempty" mapstructure:"retry"`
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty" mapstructure:"circuit_breaker"`
	Batching       *BatchingConfig       `json:"batching,omitempty" mapstructure:"batching"`
	HealthCheck    *bool                 `json:"health_check,omitempty" mapstructure:"health_check"`
	MinPriority    event.Priority        `json:"minimum_priority" mapstructure:"minimum_priority"`
	QueueSize      int                   `json:"queue_size" mapstructure:"queue_size"`
	Workers        int                   `json:"workers" mapstructure:"workers"`
}

// Validate checks runtime config for errors.
func (c *RuntimeConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	QueueSizeRange.Check(&errs, "queue_size", c.QueueSize)
	WorkersRange.Check(&errs, "workers", c.Workers)
	if c.MinPriority != "" {
		if _, err := event.ParsePriority(string(c.MinPriority)); err != nil {
			errs.Add("minimum_priority", "must be a Falco priority")
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
		batchErrs := c.Batching.Validate()
		errs.Merge("batching", batchErrs)
		// Division, not multiplication: the product of two unchecked ints can overflow.
		if len(batchErrs) == 0 && c.Batching.IsEnabled() && WorkersRange.Contains(c.Workers) &&
			c.Batching.BatchSize > MaxBatchedEvents/c.Workers {
			errs.Add("batching.batch_size", fmt.Sprintf(
				"must be at most %d with %d workers: workers × batch_size is limited to %d",
				MaxBatchedEvents/c.Workers, c.Workers, MaxBatchedEvents))
		}
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
		if b.Enabled != nil {
			b.Enabled = new(*b.Enabled)
		}
		cp.Batching = &b
	}
	if c.HealthCheck != nil {
		h := *c.HealthCheck
		cp.HealthCheck = &h
	}
	return cp
}

// ProbesDestination reports whether the destination is probed before start.
func (c *RuntimeConfig) ProbesDestination() bool { return c.HealthCheck == nil || *c.HealthCheck }

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
	MaxAttemptsRange.Check(&errs, "max_attempts", r.MaxAttempts)
	IntervalRange.Check(&errs, "initial_interval", r.InitialInterval)
	IntervalRange.Check(&errs, "max_interval", r.MaxInterval)
	MultiplierRange.Check(&errs, "multiplier", r.Multiplier)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ComputeBackoff returns the wait duration for the given attempt number, at most MaxInterval.
// The cap is compared in float64: converting an overflowing float to a Duration is not defined.
func (r *RetryConfig) ComputeBackoff(attempt int) time.Duration {
	interval := float64(r.InitialInterval) * math.Pow(r.Multiplier, float64(attempt-1))
	if math.IsNaN(interval) || interval >= float64(r.MaxInterval) {
		return r.MaxInterval
	}
	if interval < 0 {
		return 0
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
	ThresholdRange.Check(&errs, "failure_threshold", c.FailureThreshold)
	ThresholdRange.Check(&errs, "success_threshold", c.SuccessThreshold)
	ResetTimeoutRange.Check(&errs, "reset_timeout", c.ResetTimeout)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// BatchingConfig holds per-output batching settings.
type BatchingConfig struct {
	// Enabled is nil when omitted, so a per-output batching section inherits it from the defaults.
	Enabled       *bool         `json:"enabled,omitempty" mapstructure:"enabled"`
	FlushInterval time.Duration `json:"flush_interval" mapstructure:"flush_interval"`
	BatchSize     int           `json:"batch_size" mapstructure:"batch_size"`
}

// IsEnabled reports whether batching is set and enabled.
func (c *BatchingConfig) IsEnabled() bool { return c != nil && c.Enabled != nil && *c.Enabled }

// Validate checks batching settings, enabled or not: a disabled setting is enabled later by an output.
func (c *BatchingConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	BatchSizeRange.Check(&errs, "batch_size", c.BatchSize)
	FlushIntervalRange.Check(&errs, "flush_interval", c.FlushInterval)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

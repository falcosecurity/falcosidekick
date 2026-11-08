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
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestCircuitBreakerConfigValidateValid(t *testing.T) {
	cfg := output.CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		ResetTimeout:     30 * time.Second,
	}
	assert.Empty(t, cfg.Validate())
}

func TestCircuitBreakerConfigValidateZeroValues(t *testing.T) {
	cfg := output.CircuitBreakerConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestCircuitBreakerConfigValidateNegative(t *testing.T) {
	cfg := output.CircuitBreakerConfig{FailureThreshold: -1, SuccessThreshold: 2, ResetTimeout: 30 * time.Second}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
	assert.Len(t, errs, 1)
}

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker(&output.CircuitBreakerConfig{})
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(
		&output.CircuitBreakerConfig{
			FailureThreshold: 3,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	)

	completeRequest(t, cb, false)
	assert.Equal(t, CircuitClosed, cb.GetState())
	completeRequest(t, cb, false)
	assert.Equal(t, CircuitClosed, cb.GetState())
	completeRequest(t, cb, false)
	assert.Equal(t, CircuitOpen, cb.GetState())
}

func TestCircuitBreakerTransitionsToHalfOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		require.Equal(t, CircuitOpen, cb.GetState())
		time.Sleep(cfg.ResetTimeout - time.Nanosecond)
		require.Equal(t, CircuitOpen, cb.GetState())
		time.Sleep(time.Nanosecond)
		assert.Equal(t, CircuitHalfOpen, cb.GetState())
	})
}

func TestCircuitBreakerClosesAfterSuccessInHalfOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		time.Sleep(cfg.ResetTimeout)
		require.Equal(t, CircuitHalfOpen, cb.GetState())
		completeRequest(t, cb, true)
		assert.Equal(t, CircuitHalfOpen, cb.GetState())
		completeRequest(t, cb, true)
		assert.Equal(t, CircuitClosed, cb.GetState())
	})
}

func TestCircuitBreakerSuccessResetFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(&output.CircuitBreakerConfig{FailureThreshold: 3})

	completeRequest(t, cb, false)
	completeRequest(t, cb, false)
	completeRequest(t, cb, true)
	completeRequest(t, cb, false)
	completeRequest(t, cb, false)
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreakerReopensOnFailureInHalfOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cb := NewCircuitBreaker(cfg)
		for range cfg.FailureThreshold {
			completeRequest(t, cb, false)
		}
		time.Sleep(cfg.ResetTimeout)
		require.Equal(t, CircuitHalfOpen, cb.GetState())
		completeRequest(t, cb, false)
		assert.Equal(t, CircuitOpen, cb.GetState())
	})
}

func TestAllowRequestClosedAlwaysAllows(t *testing.T) {
	cb := NewCircuitBreaker(&output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: 30 * time.Second})
	for range 3 {
		completeRequest(t, cb, true)
	}
}

func TestAllowRequestOpenAlwaysBlocks(t *testing.T) {
	cb := NewCircuitBreaker(&output.CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * time.Second})
	completeRequest(t, cb, false)
	assertRequestBlocked(t, cb)
	assertRequestBlocked(t, cb)
}

func TestAllowRequestHalfOpenSingleProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cfg.SuccessThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		assertRequestBlocked(t, cb)
		time.Sleep(cfg.ResetTimeout)
		complete, allowed := cb.AllowRequest()
		require.True(t, allowed)
		assertRequestBlocked(t, cb)
		assertRequestBlocked(t, cb)
		complete(true)
		completeRequest(t, cb, true)
	})
}

func TestAllowRequestHalfOpenProbeFailureReopens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		time.Sleep(cfg.ResetTimeout)
		completeRequest(t, cb, false)
		assertRequestBlocked(t, cb)
	})
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		want  string
		state CircuitState
	}{
		{"closed", CircuitClosed},
		{"open", CircuitOpen},
		{"half-open", CircuitHalfOpen},
		{"unknown", CircuitState(99)},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.String())
		})
	}
}

func TestCircuitBreakerFailureAfterRecoverySuccessReopens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cb := NewCircuitBreaker(cfg)
		for range cfg.FailureThreshold {
			completeRequest(t, cb, false)
		}
		require.Equal(t, CircuitOpen, cb.GetState())
		time.Sleep(cfg.ResetTimeout + time.Nanosecond)
		completeRequest(t, cb, true)
		require.Equal(t, CircuitHalfOpen, cb.GetState())
		completeRequest(t, cb, false)
		assert.Equal(t, CircuitOpen, cb.GetState())
		assertRequestBlocked(t, cb)
		time.Sleep(cfg.ResetTimeout)
		completeRequest(t, cb, true)
		assert.Equal(t, CircuitHalfOpen, cb.GetState(), "successes before the failed probe must not carry over")
		completeRequest(t, cb, true)
		assert.Equal(t, CircuitClosed, cb.GetState())
	})
}

func TestCircuitBreakerOldCompletionCannotReleaseProbe(t *testing.T) {
	for _, success := range []bool{true, false} {
		name := "failure"
		if success {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := defaultRuntimeDefaults().CircuitBreaker
				cfg.FailureThreshold = 1
				cb := NewCircuitBreaker(cfg)
				oldComplete, allowed := cb.AllowRequest()
				require.True(t, allowed)
				laterComplete, allowed := cb.AllowRequest()
				require.True(t, allowed)
				completeRequest(t, cb, false)
				time.Sleep(cfg.ResetTimeout)
				probeComplete, allowed := cb.AllowRequest()
				require.True(t, allowed)
				oldComplete(success)
				assert.Equal(t, CircuitHalfOpen, cb.GetState())
				assertRequestBlocked(t, cb)
				probeComplete(true)
				assert.Equal(t, CircuitHalfOpen, cb.GetState())
				completeRequest(t, cb, true)
				require.Equal(t, CircuitClosed, cb.GetState())
				laterComplete(false)
				assert.Equal(t, CircuitClosed, cb.GetState(), "old failures must not reopen the recovered generation")
			})
		})
	}
}

func TestCircuitBreakerCompletionCountsOnce(t *testing.T) {
	cb := NewCircuitBreaker(&output.CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		ResetTimeout:     time.Minute,
	})
	complete, allowed := cb.AllowRequest()
	require.True(t, allowed)
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() { complete(false) })
	}
	callers.Wait()
	assert.Equal(t, CircuitClosed, cb.GetState())
	complete(true)
	completeRequest(t, cb, false)
	assert.Equal(t, CircuitOpen, cb.GetState(), "a repeated completion must not reset the first failure")
}

func TestCircuitBreakerDuplicateSuccessCannotReleaseNextProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		time.Sleep(cfg.ResetTimeout)
		first, allowed := cb.AllowRequest()
		require.True(t, allowed)
		first(true)
		second, allowed := cb.AllowRequest()
		require.True(t, allowed)
		first(true)
		assert.Equal(t, CircuitHalfOpen, cb.GetState())
		assertRequestBlocked(t, cb)
		second(true)
		assert.Equal(t, CircuitClosed, cb.GetState())
	})
}

func TestCircuitBreakerConcurrentProbeAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults().CircuitBreaker
		cfg.FailureThreshold = 1
		cb := NewCircuitBreaker(cfg)
		completeRequest(t, cb, false)
		time.Sleep(cfg.ResetTimeout)
		admitted := make(chan func(bool), 32)
		var callers sync.WaitGroup
		for range cap(admitted) {
			callers.Go(func() {
				if complete, allowed := cb.AllowRequest(); allowed {
					admitted <- complete
				}
			})
		}
		callers.Wait()
		require.Len(t, admitted, 1)
		complete := <-admitted
		complete(true)
		assert.Equal(t, CircuitHalfOpen, cb.GetState())
	})
}

func completeRequest(t *testing.T, cb *CircuitBreaker, success bool) {
	t.Helper()
	complete, allowed := cb.AllowRequest()
	require.True(t, allowed)
	require.NotNil(t, complete)
	complete(success)
}

func assertRequestBlocked(t *testing.T, cb *CircuitBreaker) {
	t.Helper()
	complete, allowed := cb.AllowRequest()
	assert.False(t, allowed)
	assert.Nil(t, complete)
}

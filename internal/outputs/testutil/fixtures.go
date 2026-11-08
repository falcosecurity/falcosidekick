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

package testutil

import (
	"context"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// DefaultRuntimeConfig returns the runtime defaults shared across
// api, reload, and pipeline tests.
func DefaultRuntimeConfig() output.RuntimeConfig {
	return output.RuntimeConfig{
		QueueSize: 100,
		Workers:   1,
		Retry: &output.RetryConfig{
			MaxAttempts:     1,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

// CreateValidEvent returns a complete test event.
func CreateValidEvent() *event.Event {
	return &event.Event{
		Time:     time.Date(2026, 4, 1, 10, 30, 0, 0, time.UTC),
		UUID:     "test-uuid-001",
		Output:   "File below a known binary directory opened for writing",
		Rule:     "Write below binary dir",
		Source:   "syscall",
		Hostname: "node-1",
		Priority: event.PriorityError,
		Tags:     []string{"filesystem", "mitre_persistence"},
		OutputFields: map[string]interface{}{
			"fd.name":      "/bin/hack",
			"proc.cmdline": "touch /bin/hack",
			"user.name":    "root",
		},
	}
}

// MockDriver implements output.Driver for tests.
type MockDriver struct {
	SendFunc          func(ctx context.Context, evt *event.Event) error
	InitFunc          func(ctx context.Context) error
	HealthCheckFunc   func(ctx context.Context) error
	RuntimeConfigFunc func() output.RuntimeConfig
	CloseFunc         func() error
	DriverName        string
}

func (m *MockDriver) Name() string { return m.DriverName } //nolint:revive // interface impl

func (m *MockDriver) Init(ctx context.Context) error { //nolint:revive // interface impl
	if m.InitFunc != nil {
		return m.InitFunc(ctx)
	}
	return nil
}

func (m *MockDriver) HealthCheck(ctx context.Context) error { //nolint:revive // interface impl
	if m.HealthCheckFunc != nil {
		return m.HealthCheckFunc(ctx)
	}
	return nil
}

func (m *MockDriver) RuntimeConfig() output.RuntimeConfig { //nolint:revive // interface impl
	if m.RuntimeConfigFunc != nil {
		return m.RuntimeConfigFunc()
	}
	return output.RuntimeConfig{}
}

// Close delegates to CloseFunc when set.
func (m *MockDriver) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// Send delegates to SendFunc when set.
func (m *MockDriver) Send(ctx context.Context, evt *event.Event) error {
	if m.SendFunc != nil {
		return m.SendFunc(ctx, evt)
	}
	return nil
}

// MockBatchDriver extends MockDriver with batch delivery support for tests.
type MockBatchDriver struct {
	SendBatchFunc func(ctx context.Context, events []*event.Event) error
	MockDriver
}

// SendBatch delegates to SendBatchFunc when set.
func (m *MockBatchDriver) SendBatch(ctx context.Context, events []*event.Event) error {
	if m.SendBatchFunc != nil {
		return m.SendBatchFunc(ctx, events)
	}
	return nil
}

// MustNewSender creates a Sender with empty config or fails the test.
func MustNewSender(t interface {
	Helper()
	Fatalf(string, ...any)
}, name string) *shared.Sender {
	t.Helper()
	s, err := shared.NewSender(name, &shared.HTTPConfig{})
	if err != nil {
		t.Fatalf("mustNewSender(%s): %v", name, err)
	}
	return s
}

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

package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const warmTopic = "falco"

// warmDriver returns a driver that already delivered one record to b.
func warmDriver(t *testing.T, b *fakeBroker, deliveryTimeout string) *driver {
	t.Helper()
	d, err := createOutput(map[string]any{
		"brokers":  []string{b.addr},
		"topic":    warmTopic,
		"producer": map[string]any{"delivery_timeout": deliveryTimeout},
	}, output.Deps{})
	require.NoError(t, err)
	o := d.(*driver)
	require.NoError(t, o.Init(t.Context()))
	t.Cleanup(func() { _ = o.Close() })
	require.NoError(t, o.Send(t.Context(), testutil.CreateValidEvent()), "warm-up delivery")
	require.EqualValues(t, 1, b.answered.Load())
	return o
}

// sendWithin runs send and fails the test when it does not return within limit.
func sendWithin(t *testing.T, limit time.Duration, send func() error) (time.Duration, error) {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- send() }()
	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(limit):
		t.Fatalf("send did not return within %s with the batch in flight", limit)
		return 0, nil
	}
}

var warmSends = []struct {
	send func(context.Context, *driver) error
	name string
}{
	{name: "Send", send: func(ctx context.Context, d *driver) error { return d.Send(ctx, testutil.CreateValidEvent()) }},
	{name: "SendBatch", send: func(ctx context.Context, d *driver) error {
		return d.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent(), testutil.CreateValidEvent()})
	}},
}

const warmTimeout = time.Second

// The client notices a gone broker only on its own metadata cycle; the attempt does not wait for that.
func TestWarmBrokerLossBoundsTheAttempt(t *testing.T) {
	for _, mode := range []struct {
		name  string
		mode  brokerMode
		slack time.Duration
	}{
		{name: "unanswered", mode: modeHold, slack: 500 * time.Millisecond},
		{name: "gone", mode: modeGone, slack: 500 * time.Millisecond},
	} {
		for _, tc := range warmSends {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				b := newFakeBroker(t)
				o := warmDriver(t, b, warmTimeout.String())
				b.mode.Store(int32(mode.mode))

				took, err := sendWithin(t, 10*time.Second, func() error { return tc.send(context.Background(), o) })
				select {
				case <-b.lost:
				default:
					t.Fatal("the batch never reached the broker")
				}
				require.Error(t, err)
				assert.False(t, output.IsPermanent(err), "a lost broker is retryable: %v", err)
				diagnostic, ok := errors.AsType[*shared.DeliveryError](err)
				require.True(t, ok, "want a DeliveryError, got %T", err)
				assert.Equal(t, name, diagnostic.Output)
				assert.GreaterOrEqual(t, took, warmTimeout, "failed before the delivery timeout")
				assert.LessOrEqual(t, took, warmTimeout+mode.slack, "failed late")
			})
		}
	}
}

// Waiting for the client would tie the second attempt to the metadata cycle the first one started.
func TestWarmBrokerLossBoundsConcurrentAttempts(t *testing.T) {
	for _, stagger := range []time.Duration{300 * time.Millisecond, 700 * time.Millisecond, 1200 * time.Millisecond} {
		t.Run(stagger.String(), func(t *testing.T) {
			b := newFakeBroker(t)
			o := warmDriver(t, b, warmTimeout.String())
			b.mode.Store(int32(modeGone))

			type attempt struct {
				err  error
				took time.Duration
			}
			results := make(chan attempt, 2)
			send := func() {
				start := time.Now()
				err := o.Send(context.Background(), testutil.CreateValidEvent())
				results <- attempt{err: err, took: time.Since(start)}
			}
			go send()
			<-b.lost
			time.Sleep(stagger)
			go send()
			for i := range 2 {
				select {
				case r := <-results:
					t.Logf("attempt %d: %s, %v", i, r.took.Round(time.Millisecond), r.err)
					require.Error(t, r.err)
					assert.False(t, output.IsPermanent(r.err), "a lost broker is retryable: %v", r.err)
					assert.GreaterOrEqual(t, r.took, warmTimeout, "failed before the delivery timeout")
					assert.LessOrEqual(t, r.took, warmTimeout+500*time.Millisecond, "failed late")
				case <-time.After(20 * time.Second):
					t.Fatal("an attempt did not return")
				}
			}
		})
	}
}

func TestWarmBrokerLossHonoursTheEarlierParentDeadline(t *testing.T) {
	b := newFakeBroker(t)
	o := warmDriver(t, b, "10s")
	b.mode.Store(int32(modeHold))

	const parent = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), parent)
	defer cancel()
	took, err := sendWithin(t, 3*time.Second, func() error { return o.Send(ctx, testutil.CreateValidEvent()) })
	require.Error(t, err)
	assert.False(t, output.IsPermanent(err), "a deadline is retryable: %v", err)
	assert.GreaterOrEqual(t, took, parent)
	assert.Less(t, took, parent+500*time.Millisecond)
}

func TestWarmBrokerLossRecovers(t *testing.T) {
	for _, tc := range warmSends {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBroker(t)
			o := warmDriver(t, b, warmTimeout.String())
			b.mode.Store(int32(modeGone))
			_, err := sendWithin(t, 10*time.Second, func() error { return tc.send(context.Background(), o) })
			require.Error(t, err)

			b.restart()
			require.Eventually(t, func() bool { return tc.send(context.Background(), o) == nil },
				15*time.Second, 100*time.Millisecond, "delivery did not resume after the broker returned")
		})
	}
}

func TestCloseFlushesPendingRecords(t *testing.T) {
	b := newFakeBroker(t)
	o := warmDriver(t, b, "5s")
	record, err := o.buildRecord(testutil.CreateValidEvent())
	require.NoError(t, err)
	delivered := make(chan error, 1)
	o.client.Produce(context.Background(), record, func(_ *kgo.Record, err error) { delivered <- err })
	require.NoError(t, o.Close())
	require.NoError(t, <-delivered, "Close did not flush the pending record")
	assert.EqualValues(t, 2, b.answered.Load())
}

func TestCloseIsBoundedWithTheBrokerGone(t *testing.T) {
	b := newFakeBroker(t)
	o := warmDriver(t, b, warmTimeout.String())
	b.mode.Store(int32(modeGone))
	sent := make(chan error, 1)
	go func() { sent <- o.Send(context.Background(), testutil.CreateValidEvent()) }()
	<-b.lost

	start := time.Now()
	err := o.Close()
	took := time.Since(start)
	assert.LessOrEqual(t, took, warmTimeout+500*time.Millisecond, "Close outlived the delivery timeout")
	if err != nil {
		assert.ErrorContains(t, err, "kafka close")
	}
	require.Error(t, <-sent, "the send in flight must fail")
}

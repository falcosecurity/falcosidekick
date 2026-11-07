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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestKafkaCreateValidation(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
	}{
		{config: map[string]any{"topic": "test"}, name: "missing brokers"},
		{config: map[string]any{"brokers": []string{"localhost:9092"}}, name: "missing topic"},
		{config: map[string]any{}, name: "both missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createOutput(tt.config, output.Deps{})
			assert.Error(t, err)
		})
	}
}

func TestKafkaCreateSuccess(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"localhost:9092"},
		"topic":   "falco-events",
	}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, "kafka", driver.Name())
}

func TestKafkaImplementsBatchSender(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"localhost:9092"},
		"topic":   "falco-events",
	}, output.Deps{})
	require.NoError(t, err)

	_, ok := driver.(output.BatchSender)
	assert.True(t, ok, "kafka must implement BatchSender")
}

func TestResolveACKs(t *testing.T) {
	tests := []struct {
		input string
		want  kgo.Acks
	}{
		{"all", kgo.AllISRAcks()},
		{"one", kgo.LeaderAck()},
		{"none", kgo.NoAck()},
		{"", kgo.AllISRAcks()},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := resolveACKs(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveSASL(t *testing.T) {
	tests := []struct {
		name    string
		sasl    string
		wantNil bool
		wantErr bool
	}{
		{"empty returns nil", "", true, false},
		{"none returns nil", "none", true, false},
		{"plain returns opt", "plain", false, false},
		{"scram_sha256 returns opt", "scram_sha256", false, false},
		{"scram_sha512 returns opt", "scram_sha512", false, false},
		{"unknown returns error", "kerberos", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{Auth: kafkaAuth{SASL: tt.sasl, Username: "user", Password: "pass"}}
			opt, err := resolveSASL(cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, opt)
			} else {
				assert.NotNil(t, opt)
			}
		})
	}
}

func TestResolveCompression(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"gzip", "gzip"},
		{"snappy", "snappy"},
		{"lz4", "lz4"},
		{"zstd", "zstd"},
		{"none explicit", "none"},
		{"empty defaults to none", ""},
		{"uppercase normalizes", "GZIP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := resolveCompression(tt.input)
			assert.Len(t, opts, 1, "must return exactly one option")
		})
	}
}

func TestResolveBalancer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"round_robin", "round_robin", 1},
		{"least_backup", "least_backup", 1},
		{"sticky", "sticky", 1},
		{"empty returns nil", "", 0},
		{"unknown returns nil", "random", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := resolveBalancer(tt.input)
			assert.Len(t, opts, tt.wantLen)
		})
	}
}

func TestCreateOutputAsync(t *testing.T) {
	out, err := createOutput(map[string]any{
		"brokers":  []string{"localhost:9092"},
		"topic":    "events",
		"producer": map[string]any{"async": true, "delivery_timeout": "1s"},
	}, output.Deps{})
	require.NoError(t, err)

	o, ok := out.(*driver)
	require.True(t, ok)
	assert.True(t, o.cfg.Producer.Async)
}

func TestCreateOutputTopicCreation(t *testing.T) {
	tests := []struct {
		name          string
		topicCreation bool
	}{
		{"enabled", true},
		{"disabled", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := createOutput(map[string]any{
				"brokers":  []string{"localhost:9092"},
				"topic":    "events",
				"producer": map[string]any{"auto_create_topic": tt.topicCreation},
			}, output.Deps{})
			require.NoError(t, err)
			assert.Equal(t, "kafka", out.Name())
		})
	}
}

func TestCreateOutputClientID(t *testing.T) {
	out, err := createOutput(map[string]any{
		"brokers":  []string{"localhost:9092"},
		"topic":    "events",
		"producer": map[string]any{"client_id": "my-producer"},
	}, output.Deps{})
	require.NoError(t, err)
	assert.NotNil(t, out)
}

func TestCreateOutputTLS(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
	}{
		{
			name: "tls with default insecure_skip_verify",
			config: map[string]any{
				"brokers":     []string{"localhost:9092"},
				"topic":       "events",
				"tls_enabled": true,
			},
		},
		{
			name: "tls with insecure_skip_verify false",
			config: map[string]any{
				"brokers":     []string{"localhost:9092"},
				"topic":       "events",
				"tls_enabled": true,
				"tls": map[string]any{
					"insecure_skip_verify": false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := createOutput(tt.config, output.Deps{})
			require.NoError(t, err)
			assert.NotNil(t, driver)
		})
	}
}

func TestCreateOutputSASLVariants(t *testing.T) {
	tests := []struct {
		name string
		sasl string
	}{
		{"plain", "plain"},
		{"scram256", "scram_sha256"},
		{"scram512", "scram_sha512"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := createOutput(map[string]any{
				"brokers": []string{"localhost:9092"},
				"topic":   "events",
				"auth":    map[string]any{"sasl": tt.sasl, "username": "user", "password": "pass"},
			}, output.Deps{})
			require.NoError(t, err)
			assert.NotNil(t, driver)
		})
	}
}

func TestCreateOutputAcceptsRuntimeOverrides(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:9092"},
		"topic":   "events",
		"runtime": map[string]any{
			"minimum_priority": "error",
			"queue_size":       3000,
			"workers":          8,
			"batching": map[string]any{
				"enabled":    true,
				"batch_size": 500,
			},
		},
	}, output.Deps{})
	require.NoError(t, err, "runtime override keys must not be rejected")
	assert.Equal(t, "kafka", d.Name())
	pCfg := d.RuntimeConfig()
	assert.Equal(t, 3000, pCfg.QueueSize)
	assert.Equal(t, 8, pCfg.Workers)
	assert.Equal(t, event.PriorityError, pCfg.MinPriority)
	require.NotNil(t, pCfg.Batching)
	assert.True(t, pCfg.Batching.Enabled)
}

func TestCreateOutputRejectsUnknownKeys(t *testing.T) {
	_, err := createOutput(map[string]any{
		"brokers":     []string{"localhost:9092"},
		"topic":       "events",
		"unknown_key": "value",
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_key")
}

// TLS settings without tls_enabled used to be ignored, so the client connected in clear text.
func TestCreateOutputRejectsTLSWithoutTLSEnabled(t *testing.T) {
	_, err := createOutput(map[string]any{
		"brokers": []string{"localhost:9092"},
		"topic":   "events",
		"tls":     map[string]any{"server_name": "kafka.internal"},
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls: is set but tls_enabled is false")
}

func TestCreateOutputSASLInvalid(t *testing.T) {
	_, err := createOutput(map[string]any{
		"brokers": []string{"localhost:9092"},
		"topic":   "events",
		"auth":    map[string]any{"sasl": "kerberos"},
	}, output.Deps{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be plain/scram_sha256/scram_sha512")
}

func TestCreateOutputAllOptions(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers":     []string{"broker1:9092", "broker2:9092"},
		"topic":       "falco",
		"auth":        map[string]any{"sasl": "plain", "username": "u", "password": "p"},
		"tls_enabled": true,
		"producer":    map[string]any{"client_id": "cid", "compression": "zstd", "balancer": "round_robin", "required_acks": "one", "async": true, "auto_create_topic": true},
	}, output.Deps{})
	require.NoError(t, err)

	o, ok := d.(*driver)
	require.True(t, ok)
	assert.Equal(t, "falco", o.cfg.Topic)
	assert.True(t, o.cfg.Producer.Async)
}

func TestCloseNilClient(t *testing.T) {
	o := &driver{cfg: config{Topic: "test"}}
	err := o.Close()
	assert.NoError(t, err)
}

func TestCreateOutputMultiBroker(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"b1:9092", "b2:9092", "b3:9092"},
		"topic":   "t",
	}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, "kafka", driver.Name())
}

func TestInitCreateClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:19092"},
		"topic":   "events",
	}, output.Deps{})
	require.NoError(t, err)

	o, ok := d.(*driver)
	require.True(t, ok)
	assert.Nil(t, o.client, "client must be nil before Init")

	err = o.Init(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, o.client, "client must be set after Init")
	_ = o.Close()
}

func TestCloseWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:19092"},
		"topic":   "events",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	assert.NotNil(t, o.client)

	err = o.Close()
	assert.NoError(t, err)
}

func TestSendSyncWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:19092"},
		"topic":   "events",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = o.Send(ctx, &event.Event{
		Rule:         "test",
		Priority:     event.PriorityWarning,
		Time:         time.Now(),
		Source:       "syscall",
		OutputFields: map[string]interface{}{"a": "b"},
	})
	// No broker is running.
	assert.Error(t, err)
}

func TestSendAsyncWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers":  []string{"localhost:19092"},
		"topic":    "events",
		"producer": map[string]any{"async": true, "delivery_timeout": "1s"},
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	err = o.Send(context.Background(), &event.Event{
		Rule:         "test",
		Priority:     event.PriorityWarning,
		Time:         time.Now(),
		Source:       "syscall",
		OutputFields: map[string]interface{}{"a": "b"},
	})
	// Async produce returns before any broker answers.
	assert.NoError(t, err)
}

func TestSendBatchSyncWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:19092"},
		"topic":   "events",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events := []*event.Event{
		{Rule: "r1", Priority: event.PriorityWarning, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"a": "b"}},
		{Rule: "r2", Priority: event.PriorityError, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"c": "d"}},
	}
	err = o.SendBatch(ctx, events)
	// No broker is running.
	assert.Error(t, err)
}

func TestSendBatchAsyncWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers":  []string{"localhost:19092"},
		"topic":    "events",
		"producer": map[string]any{"async": true, "delivery_timeout": "1s"},
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	events := []*event.Event{
		{Rule: "r1", Priority: event.PriorityWarning, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"a": "b"}},
	}
	err = o.SendBatch(context.Background(), events)
	assert.NoError(t, err)
}

func TestHealthCheckWithClient(t *testing.T) {
	d, err := createOutput(map[string]any{
		"brokers": []string{"localhost:19092"},
		"topic":   "events",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = o.HealthCheck(ctx)
	// No broker is running.
	assert.Error(t, err)
}

func TestValidBrokerReachesTheClientAddress(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if conn, acceptErr := listener.Accept(); acceptErr == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	d, err := createOutput(map[string]any{"brokers": []string{listener.Addr().String()}, "topic": "falco"}, output.Deps{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	require.NoError(t, d.Init(ctx))
	t.Cleanup(func() { _ = d.Close() })
	require.Error(t, d.Send(ctx, testutil.CreateValidEvent()), "the listener speaks no Kafka protocol")

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("client never connected to the configured broker")
	}
}

func TestSchemeBrokerRejected(t *testing.T) {
	_, err := createOutput(map[string]any{"brokers": []string{"http://localhost:9092"}, "topic": "falco"}, output.Deps{})
	require.ErrorContains(t, err, "must be host:port without a scheme")
}

func TestDeliveryTimeoutConfig(t *testing.T) {
	for _, tc := range []struct {
		value   any
		name    string
		wantErr string
		want    time.Duration
	}{
		{name: "default", want: 10 * time.Second},
		{name: "explicit", value: "2500ms", want: 2500 * time.Millisecond},
		{name: "minimum", value: "1s", want: time.Second},
		{name: "below minimum", value: "999ms", wantErr: "delivery_timeout: must be at least 1s"},
		{name: "zero", value: "0s", wantErr: "delivery_timeout: must be at least 1s"},
		{name: "negative", value: "-1s", wantErr: "delivery_timeout: must be at least 1s"},
		{name: "unparsable", value: "soon", wantErr: "delivery_timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			producer := map[string]any{}
			if tc.value != nil {
				producer["delivery_timeout"] = tc.value
			}
			d, err := createOutput(map[string]any{"brokers": []string{"127.0.0.1:1"}, "topic": "events", "producer": producer}, output.Deps{})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, d.(*driver).cfg.Producer.DeliveryTimeout)
		})
	}
}

func TestDeliveryTimeoutSchemaDefault(t *testing.T) {
	for _, field := range OutputType.Schema.Fields {
		if field.Name == "producer.delivery_timeout" {
			assert.Equal(t, "10s", field.Default)
			return
		}
	}
	t.Fatal("producer.delivery_timeout missing from schema")
}

func unreachableDriver(t *testing.T, async bool) *driver {
	t.Helper()
	d, err := createOutput(map[string]any{
		"brokers":  []string{"127.0.0.1:1"},
		"topic":    "events",
		"producer": map[string]any{"async": async, "delivery_timeout": "1s"},
	}, output.Deps{})
	require.NoError(t, err)
	o := d.(*driver)
	require.NoError(t, o.Init(context.Background()))
	return o
}

func TestSyncSendIsBoundedByDeliveryTimeout(t *testing.T) {
	o := unreachableDriver(t, false)
	defer func() { _ = o.Close() }()

	start := time.Now()
	err := o.Send(context.Background(), &event.Event{Rule: "r", Priority: event.PriorityWarning, Time: time.Now(), OutputFields: map[string]any{}})
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestCloseIsBoundedByDeliveryTimeout(t *testing.T) {
	o := unreachableDriver(t, true)
	for range 10 {
		require.NoError(t, o.Send(context.Background(), &event.Event{Rule: "r", Priority: event.PriorityWarning, Time: time.Now(), OutputFields: map[string]any{}}))
	}

	start := time.Now()
	err := o.Close()
	assert.Less(t, time.Since(start), 5*time.Second)
	if err != nil {
		assert.ErrorContains(t, err, "kafka close")
	}
}

func TestAsyncFailureReachesLateFailureHandler(t *testing.T) {
	o := unreachableDriver(t, true)
	var mu sync.Mutex
	var failures []error
	o.SetLateFailureHandler(func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	})
	for range 3 {
		require.NoError(t, o.Send(context.Background(), &event.Event{Rule: "r", Priority: event.PriorityWarning, Time: time.Now(), OutputFields: map[string]any{}}))
	}
	_ = o.Close()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, failures, 3)
	for _, err := range failures {
		assert.ErrorContains(t, err, "kafka async produce")
	}
}

func TestHealthCheckClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		name string
		want bool
	}{
		{name: "sasl authentication failed", err: fmt.Errorf("sasl: %w", kerr.SaslAuthenticationFailed), want: true},
		{name: "unsupported sasl mechanism", err: kerr.UnsupportedSaslMechanism, want: true},
		{name: "illegal sasl state", err: kerr.IllegalSaslState, want: true},
		{name: "unknown authority", err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, want: true},
		{name: "connection refused", err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "broker not available", err: kerr.BrokerNotAvailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isMisconfiguration(tc.err))
		})
	}
}

func TestHealthCheckUnreachableBrokerIsTransient(t *testing.T) {
	d, err := createOutput(map[string]any{"brokers": []string{"127.0.0.1:1"}, "topic": "falco"}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err = d.HealthCheck(ctx)
	require.Error(t, err)
	assert.NotErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "kafka healthcheck")
}

func TestAsyncFailureWithoutHandlerOnlyLogs(t *testing.T) {
	o := unreachableDriver(t, true)
	require.NoError(t, o.Send(context.Background(), &event.Event{Rule: "r", Priority: event.PriorityWarning, Time: time.Now(), OutputFields: map[string]any{}}))
	_ = o.Close()
}

// franz-go appends the broker's error message, which can echo submitted values.
func TestDeliveryErrorKeepsOnlyProtocolCodes(t *testing.T) {
	const echoed = "echoed-by-broker"
	sasl := fmt.Errorf("%w: invalid credentials for user %s", kerr.SaslAuthenticationFailed, echoed)
	err := newDeliveryError(shared.OpHealthcheck, sasl)
	assert.Equal(t, "kafka healthcheck: SASL_AUTHENTICATION_FAILED", err.Error())
	assert.ErrorIs(t, err, kerr.SaslAuthenticationFailed)
	assert.NotContains(t, fmt.Sprintf("%v %+v %q", err, err, err), echoed)

	network := newDeliveryError(shared.OpSend, fmt.Errorf("dial %s: %w", echoed, syscall.ECONNREFUSED))
	assert.Equal(t, "kafka send: connection refused", network.Error())
}

func TestDeliveryErrorPermanence(t *testing.T) {
	tests := []struct {
		err       error
		name      string
		permanent bool
	}{
		{name: "message too large", err: fmt.Errorf("%w (uncompressed_bytes=9)", kerr.MessageTooLarge), permanent: true},
		{name: "topic authorization", err: kerr.TopicAuthorizationFailed, permanent: true},
		{name: "invalid record", err: kerr.InvalidRecord, permanent: true},
		{name: "unknown server error", err: kerr.UnknownServerError},
		{name: "not leader", err: kerr.NotLeaderForPartition},
		{name: "unknown topic", err: kerr.UnknownTopicOrPartition},
		{name: "record timeout", err: kgo.ErrRecordTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newDeliveryError(shared.OpSend, tt.err)
			assert.Equal(t, tt.permanent, output.IsPermanent(err))
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestProducedBatchIsPermanentOnlyWhenEveryRecordIs(t *testing.T) {
	record := func() *kgo.Record { return &kgo.Record{Topic: "events"} }
	tooLarge := kgo.ProduceResult{Record: record(), Err: kerr.MessageTooLarge}
	notEnoughReplicas := kgo.ProduceResult{Record: record(), Err: kerr.NotEnoughReplicas}
	delivered := kgo.ProduceResult{Record: record()}
	d := &driver{purged: make(map[string]time.Time)}

	for _, tc := range []struct {
		name      string
		want      string
		results   kgo.ProduceResults
		permanent bool
	}{
		{name: "delivered", results: kgo.ProduceResults{delivered, delivered}},
		{name: "one permanent", results: kgo.ProduceResults{tooLarge, delivered},
			want: "kafka send: 1 of 2 records failed, first: MESSAGE_TOO_LARGE", permanent: true},
		{name: "permanent and transient", results: kgo.ProduceResults{tooLarge, notEnoughReplicas, delivered},
			want: "kafka send: 2 of 3 records failed, first: MESSAGE_TOO_LARGE"},
		{name: "transient and permanent", results: kgo.ProduceResults{notEnoughReplicas, tooLarge},
			want: "kafka send: 2 of 2 records failed, first: NOT_ENOUGH_REPLICAS"},
		{name: "every record permanent", results: kgo.ProduceResults{tooLarge, tooLarge},
			want: "kafka send: 2 of 2 records failed, first: MESSAGE_TOO_LARGE", permanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := d.produced(context.Background(), tc.results)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.Equal(t, tc.permanent, output.IsPermanent(err), "order of the results must not decide")
		})
	}
}

func TestRecreatedTopicIsPurgedOncePerRecovery(t *testing.T) {
	client, err := kgo.NewClient(kgo.SeedBrokers("127.0.0.1:1"))
	require.NoError(t, err)
	t.Cleanup(client.Close)
	d := &driver{client: client, purged: make(map[string]time.Time)}
	stale := &kgo.Record{Topic: "events", Timestamp: time.Now()}
	other := &kgo.Record{Topic: "other", Timestamp: time.Now()}

	d.forgetRecreatedTopic(stale, kerr.UnknownTopicID)
	first := d.purged["events"]
	require.False(t, first.IsZero(), "the first failure purges")

	d.forgetRecreatedTopic(stale, kerr.UnknownTopicID)
	assert.Equal(t, first, d.purged["events"], "a record produced before the purge does not purge again")

	d.forgetRecreatedTopic(other, kerr.UnknownTopicID)
	assert.False(t, d.purged["other"].IsZero(), "topics are tracked separately")

	fresh := &kgo.Record{Topic: "events", Timestamp: time.Now().Add(time.Second)}
	d.forgetRecreatedTopic(fresh, kerr.UnknownTopicID)
	assert.True(t, d.purged["events"].After(first), "a record produced after the purge can purge a later recreation")

	d.forgetRecreatedTopic(&kgo.Record{Topic: "unrelated"}, kerr.NotLeaderForPartition)
	assert.NotContains(t, d.purged, "unrelated")
}

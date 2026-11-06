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

package gcppubsub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"cloud.google.com/go/pubsub/v2/pstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testProject = "fsk-test"
	testTopic   = "falco-events"
	sentinel    = "s3cret-sentinel"
)

// serviceAccountJSON carries sentinel in an invalid private key.
var serviceAccountJSON = fmt.Sprintf(`{"type":"service_account","project_id":"p","private_key_id":"k",`+
	`"private_key":"-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n",`+
	`"client_email":"fsk@p.iam.gserviceaccount.com","client_id":"1","token_uri":"https://oauth2.googleapis.com/token"}`, sentinel)

// errorReactor answers every call of one method with a gRPC status.
type errorReactor struct {
	err error
}

func (r errorReactor) React(any) (handled bool, ret any, err error) { return true, nil, r.err }

// fakeServer starts an in-process Pub/Sub server with testTopic created.
func fakeServer(t *testing.T, opts ...pstest.ServerReactorOption) *pstest.Server {
	t.Helper()
	srv := pstest.NewServer(opts...)
	t.Cleanup(func() { _ = srv.Close() })
	d := initDriver(t, map[string]any{"project_id": testProject, "topic": testTopic, "emulator_host": srv.Addr})
	_, err := d.client.TopicAdminClient.CreateTopic(context.Background(), &pubsubpb.Topic{Name: d.publisher.String()})
	require.NoError(t, err)
	return srv
}

func newDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	return d.(*driver)
}

func initDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d := newDriver(t, cfg)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func emulatorConfig(srv *pstest.Server) map[string]any {
	return map[string]any{"project_id": testProject, "topic": testTopic, "emulator_host": srv.Addr}
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	assert.Equal(t, "gcppubsub", OutputType.Name)
	assert.True(t, fields["project_id"].Required)
	assert.True(t, fields["topic"].Required)
	assert.True(t, fields["credentials"].Secret)
	assert.False(t, fields["credentials"].Required)
	assert.Equal(t, "map", fields["custom_attributes"].Type)
	assert.Contains(t, fields, "endpoint")
	assert.Contains(t, fields, "emulator_host")
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func TestConfigValidation(t *testing.T) {
	longKey := strings.Repeat("k", maxAttributeKeyBytes+1)
	tooMany := map[string]any{}
	for i := range maxAttributes + 1 {
		tooMany[fmt.Sprintf("k%d", i)] = "v"
	}
	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr string
	}{
		{name: "minimal", cfg: map[string]any{"project_id": "p", "topic": "falco"}},
		{name: "all fields", cfg: map[string]any{
			"project_id": "p", "topic": "falco.events_1", "endpoint": "europe-west1-pubsub.googleapis.com:443",
			"custom_attributes": map[string]any{"env": "prod", "n": 1}, "credentials": serviceAccountJSON,
		}},
		{name: "emulator", cfg: map[string]any{"project_id": "p", "topic": "falco", "emulator_host": "localhost:8085"}},
		{name: "missing project", cfg: map[string]any{"topic": "falco"}, wantErr: "project_id: is required"},
		{name: "blank project", cfg: map[string]any{"project_id": " ", "topic": "falco"}, wantErr: "project_id: is required"},
		{name: "project path", cfg: map[string]any{"project_id": "projects/p", "topic": "falco"}, wantErr: "project_id: must be a project ID"},
		{name: "missing topic", cfg: map[string]any{"project_id": "p"}, wantErr: "topic: is required"},
		{name: "topic too short", cfg: map[string]any{"project_id": "p", "topic": "ab"}, wantErr: "topic: must be a topic ID"},
		{name: "topic path", cfg: map[string]any{"project_id": "p", "topic": "projects/p/topics/t"}, wantErr: "topic: must be a topic ID"},
		{name: "topic reserved", cfg: map[string]any{"project_id": "p", "topic": "google-events"}, wantErr: "topic: must be a topic ID"},
		{name: "topic starts with digit", cfg: map[string]any{"project_id": "p", "topic": "1falco"}, wantErr: "topic: must be a topic ID"},
		{name: "endpoint with scheme", cfg: map[string]any{"project_id": "p", "topic": "falco", "endpoint": "https://pubsub.googleapis.com"}, wantErr: "endpoint:"},
		{name: "emulator without port", cfg: map[string]any{"project_id": "p", "topic": "falco", "emulator_host": "localhost"}, wantErr: "emulator_host:"},
		{name: "emulator with endpoint", cfg: map[string]any{"project_id": "p", "topic": "falco", "emulator_host": "localhost:8085", "endpoint": "pubsub.googleapis.com:443"}, wantErr: "emulator_host: cannot be combined with endpoint"},
		{name: "emulator with credentials", cfg: map[string]any{"project_id": "p", "topic": "falco", "emulator_host": "localhost:8085", "credentials": serviceAccountJSON}, wantErr: "emulator_host: cannot be combined with credentials"},
		{name: "empty attribute name", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": map[string]any{"": "v"}}, wantErr: "attribute names must not be empty"},
		{name: "reserved attribute", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": map[string]any{"googkey": "v"}}, wantErr: "reserved"},
		{name: "long attribute name", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": map[string]any{longKey: "v"}}, wantErr: "name exceeds 256 bytes"},
		{name: "long attribute value", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": map[string]any{"k": strings.Repeat("v", maxAttributeValBytes+1)}}, wantErr: "value exceeds 1024 bytes"},
		{name: "too many attributes", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": tooMany}, wantErr: "at most 100 attributes"},
		{name: "unknown key", cfg: map[string]any{"project_id": "p", "topic": "falco", "projectid": "p"}, wantErr: "unknown keys"},
		{name: "attributes not a map", cfg: map[string]any{"project_id": "p", "topic": "falco", "custom_attributes": "a=b"}, wantErr: "custom_attributes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OutputType.New(tt.cfg, output.Deps{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.True(t, strings.HasPrefix(err.Error(), "gcppubsub"), err.Error())
		})
	}
}

func TestCredentials(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(serviceAccountJSON))
	tests := []struct {
		name    string
		value   string
		wantErr string
		want    string
	}{
		{name: "raw JSON", value: serviceAccountJSON, want: "service_account"},
		{name: "base64", value: encoded, want: "service_account"},
		{name: "base64 with newline", value: encoded + "\n", want: "service_account"},
		{name: "external account", value: `{"type":"external_account","audience":"a"}`, want: "external_account"},
		{name: "authorized user", value: `{"type":"authorized_user"}`, want: "authorized_user"},
		{name: "impersonated", value: `{"type":"impersonated_service_account"}`, want: "impersonated_service_account"},
		{name: "not base64", value: "!" + sentinel, wantErr: "must be a credentials JSON document"},
		{name: "base64 of text", value: base64.StdEncoding.EncodeToString([]byte(sentinel)), wantErr: "must be a credentials JSON document"},
		{name: "invalid JSON", value: `{"type":"` + sentinel, wantErr: "must be a credentials JSON document"},
		{name: "unsupported type", value: `{"type":"` + sentinel + `"}`, wantErr: "type must be service_account"},
		{name: "missing type", value: `{"private_key":"` + sentinel + `"}`, wantErr: "type must be service_account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := OutputType.New(map[string]any{"project_id": "p", "topic": "falco", "credentials": tt.value}, output.Deps{})
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "credentials: "+tt.wantErr)
				assert.NotContains(t, err.Error(), sentinel)
				return
			}
			require.NoError(t, err)
			drv := d.(*driver)
			assert.Equal(t, tt.want, string(drv.cfg.credentialsType))
			assert.True(t, json.Valid(drv.cfg.credentialsJSON))
		})
	}
}

func TestInitRejectsUnusableCredentials(t *testing.T) {
	d := newDriver(t, map[string]any{"project_id": "p", "topic": "falco", "credentials": serviceAccountJSON})
	err := d.Init(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "cannot load credentials")
	assert.NotContains(t, err.Error(), sentinel)
	require.NoError(t, d.Close())
}

func TestInitWithoutApplicationDefaultCredentials(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", t.TempDir()+"/missing.json")
	d := newDriver(t, map[string]any{"project_id": "p", "topic": "falco"})
	err := d.Init(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "application default credentials not found")
}

func TestNotReadyBeforeInit(t *testing.T) {
	d := newDriver(t, map[string]any{"project_id": "p", "topic": "falco"})
	assert.ErrorIs(t, d.Send(context.Background(), testutil.CreateValidEvent()), core.ErrNotReady)
	assert.ErrorIs(t, d.HealthCheck(context.Background()), core.ErrNotReady)
	assert.NoError(t, d.Close())
	assert.Equal(t, "gcppubsub", d.Name())
	assert.Equal(t, output.RuntimeConfig{}, d.RuntimeConfig())
}

func TestSendPublishesEventWithAttributes(t *testing.T) {
	srv := fakeServer(t)
	cfg := emulatorConfig(srv)
	cfg["custom_attributes"] = map[string]any{"env": "prod", "cluster": "eu-1"}
	d := initDriver(t, cfg)

	evt := testutil.CreateValidEvent()
	require.NoError(t, d.Send(context.Background(), evt))

	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	var got event.Event
	require.NoError(t, json.Unmarshal(msgs[0].Data, &got))
	assert.Equal(t, evt.Rule, got.Rule)
	assert.Equal(t, evt.Priority, got.Priority)
	assert.Equal(t, evt.Output, got.Output)
	assert.Equal(t, map[string]string{"env": "prod", "cluster": "eu-1"}, msgs[0].Attributes)
}

func TestSendWithoutAttributes(t *testing.T) {
	srv := fakeServer(t)
	d := initDriver(t, emulatorConfig(srv))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	assert.Empty(t, msgs[0].Attributes)
}

func TestSendBatchPublishesEveryEvent(t *testing.T) {
	srv := fakeServer(t)
	d := initDriver(t, emulatorConfig(srv))
	events := make([]*event.Event, 5)
	for i := range events {
		events[i] = testutil.CreateValidEvent()
		events[i].Rule = fmt.Sprintf("rule-%d", i)
	}
	require.NoError(t, d.SendBatch(context.Background(), events))

	rules := map[string]bool{}
	for _, m := range srv.Messages() {
		var got event.Event
		require.NoError(t, json.Unmarshal(m.Data, &got))
		rules[got.Rule] = true
	}
	assert.Len(t, rules, 5)
}

func TestSendFailures(t *testing.T) {
	t.Run("missing topic", func(t *testing.T) {
		srv := pstest.NewServer()
		t.Cleanup(func() { _ = srv.Close() })
		d := initDriver(t, emulatorConfig(srv))
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.Equal(t, "destination rejects the delivery: gcppubsub publish: NotFound", err.Error())
		assert.True(t, output.IsPermanent(err))
	})
	t.Run("batch reports every failure", func(t *testing.T) {
		srv := fakeServer(t, pstest.ServerReactorOption{
			FuncName: "Publish",
			Reactor:  errorReactor{err: status.Error(codes.PermissionDenied, "denied "+sentinel)},
		})
		d := initDriver(t, emulatorConfig(srv))
		err := d.SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
		require.Error(t, err)
		assert.Equal(t, "destination rejects the delivery: 2 of 2 messages failed: gcppubsub publish: PermissionDenied", err.Error())
		assert.True(t, output.IsPermanent(err), "every message was rejected for good")
		assert.NotContains(t, err.Error(), sentinel)
	})
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		err          error
		name         string
		want         string
		noTopic      bool
		misconfigure bool
	}{
		{name: "topic exists"},
		{name: "topic missing", noTopic: true, want: "topic check: NotFound", misconfigure: true},
		{name: "rejected credentials", err: status.Error(codes.Unauthenticated, sentinel), want: "topic check: Unauthenticated", misconfigure: true},
		{name: "invalid name", err: status.Error(codes.InvalidArgument, sentinel), want: "topic check: InvalidArgument", misconfigure: true},
		{name: "no topics.get permission", err: status.Error(codes.PermissionDenied, sentinel), want: "topic check: PermissionDenied"},
		{name: "unavailable is retried until the deadline", err: status.Error(codes.Unavailable, sentinel), want: "topic check: timeout (deadline exceeded)"},
		{name: "internal", err: status.Error(codes.Internal, sentinel), want: "topic check: Internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []pstest.ServerReactorOption
			if tt.err != nil {
				opts = append(opts, pstest.ServerReactorOption{FuncName: "GetTopic", Reactor: errorReactor{err: tt.err}})
			}
			var srv *pstest.Server
			if tt.noTopic {
				srv = pstest.NewServer(opts...)
				t.Cleanup(func() { _ = srv.Close() })
			} else {
				srv = fakeServer(t, opts...)
			}
			d := initDriver(t, emulatorConfig(srv))
			ctx, cancel := context.WithTimeout(context.Background(), testutil.ReturnWithin)
			defer cancel()
			err := d.HealthCheck(ctx)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "gcppubsub "+tt.want)
			assert.NotContains(t, err.Error(), sentinel)
			assert.Equal(t, tt.misconfigure, errors.Is(err, output.ErrMisconfigured))
		})
	}
}

func TestReturnsWhenContextEnds(t *testing.T) {
	d := initDriver(t, map[string]any{"project_id": testProject, "topic": testTopic, "emulator_host": testutil.HangingTCPServer(t)})
	calls := map[string]func(context.Context) error{
		"Send": func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) },
		"SendBatch": func(ctx context.Context) error {
			return d.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
		},
		"HealthCheck": d.HealthCheck,
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := testutil.RequireReturnsOnCancel(t, name, call)
			assert.Contains(t, err.Error(), "timeout (deadline exceeded)")
			assert.False(t, errors.Is(err, output.ErrMisconfigured))
		})
	}

	start := time.Now()
	err := d.Close()
	assert.Less(t, time.Since(start), closeTimeout+testutil.ReturnWithin)
	require.Error(t, err)
	assert.Equal(t, "gcppubsub: flush did not complete within 10s", err.Error())
	assert.NoError(t, d.Close(), "Close is idempotent")
}

func TestCloseFlushesAndStopsPublishing(t *testing.T) {
	srv := fakeServer(t)
	d := newDriver(t, emulatorConfig(srv))
	require.NoError(t, d.Init(context.Background()))
	res := d.publisher.Publish(context.Background(), &pubsub.Message{Data: []byte("{}")})
	require.NoError(t, d.Close())
	_, err := res.Get(context.Background())
	require.NoError(t, err, "Close delivers buffered messages")
	assert.Len(t, srv.Messages(), 1)

	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Equal(t, "gcppubsub publish: request failed", err.Error())
}

func TestSafeError(t *testing.T) {
	const rejected = "destination rejects the delivery: "
	tests := []struct {
		err       error
		name      string
		want      string
		permanent bool
	}{
		{name: "canceled", err: context.Canceled, want: "gcppubsub publish: request canceled"},
		{name: "deadline", err: fmt.Errorf("wrapped: %w", context.DeadlineExceeded), want: "gcppubsub publish: timeout (deadline exceeded)"},
		{name: "status canceled", err: status.Error(codes.Canceled, sentinel), want: "gcppubsub publish: request canceled"},
		{name: "status deadline", err: status.Error(codes.DeadlineExceeded, sentinel), want: "gcppubsub publish: timeout (deadline exceeded)"},
		{name: "resource exhausted", err: status.Error(codes.ResourceExhausted, sentinel), want: "gcppubsub publish: ResourceExhausted"},
		{name: "unavailable", err: status.Error(codes.Unavailable, sentinel), want: "gcppubsub publish: Unavailable"},
		{name: "not found", err: status.Error(codes.NotFound, sentinel), want: rejected + "gcppubsub publish: NotFound", permanent: true},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, sentinel), want: rejected + "gcppubsub publish: PermissionDenied", permanent: true},
		{name: "invalid argument", err: status.Error(codes.InvalidArgument, sentinel), want: rejected + "gcppubsub publish: InvalidArgument", permanent: true},
		{name: "oversized", err: pubsub.ErrOversizedMessage, want: rejected + "gcppubsub publish: message too large", permanent: true},
		{name: "other", err: errors.New(sentinel), want: "gcppubsub publish: request failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := safeError("publish", tt.err)
			assert.Equal(t, tt.want, err.Error())
			assert.Equal(t, tt.permanent, output.IsPermanent(err))
			assert.NotContains(t, fmt.Sprintf("%v %+v %s", err, err, err), sentinel)
		})
	}
}

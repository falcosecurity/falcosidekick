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

package awss3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws/awstest"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const bucket = "falco-events"

func newDriver(t *testing.T, endpoint string, extra map[string]any) output.Driver {
	t.Helper()
	cfg := awstest.Config(endpoint, map[string]any{"bucket": bucket, "use_path_style": true})
	for k, v := range extra {
		cfg[k] = v
	}
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr string
	}{
		{name: "minimal", cfg: map[string]any{"bucket": bucket}},
		{name: "all fields", cfg: map[string]any{"bucket": "a.b-c", "prefix": "/x/y/", "object_canned_acl": "private", "use_path_style": true, "endpoint": "http://minio:9000"}},
		{name: "missing bucket", cfg: map[string]any{}, wantErr: "bucket: is required"},
		{name: "uppercase bucket", cfg: map[string]any{"bucket": "Falco"}, wantErr: "bucket: invalid bucket name"},
		{name: "short bucket", cfg: map[string]any{"bucket": "ab"}, wantErr: "bucket: invalid bucket name"},
		{name: "double dot bucket", cfg: map[string]any{"bucket": "a..b"}, wantErr: "bucket: invalid bucket name"},
		{name: "bad acl", cfg: map[string]any{"bucket": bucket, "object_canned_acl": "everyone"}, wantErr: "object_canned_acl: must be one of"},
		{name: "unknown key", cfg: map[string]any{"bucket": bucket, "bukket": "x"}, wantErr: "unknown keys: bukket"},
		{name: "minimum_priority only under runtime", cfg: map[string]any{"bucket": bucket, "minimum_priority": "error"}, wantErr: "unknown keys"},
		{name: "shared aws validation", cfg: map[string]any{"bucket": bucket, "access_key_id": "a"}, wantErr: "secret_access_key: is required"},
		{name: "bad endpoint", cfg: map[string]any{"bucket": bucket, "endpoint": "minio:9000"}, wantErr: "endpoint: must be an http or https URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			t.Setenv("AWS_REGION", "us-east-1")
			d, err := OutputType.New(tt.cfg, output.Deps{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, name, d.Name())
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCreateRequiresRegion(t *testing.T) {
	awstest.Isolate(t)
	_, err := OutputType.New(map[string]any{"bucket": bucket}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "awss3: region: is required")
}

func TestDefaults(t *testing.T) {
	awstest.Isolate(t)
	d := newDriver(t, "http://127.0.0.1:1", map[string]any{"prefix": "", "runtime": map[string]any{"minimum_priority": "error"}}).(*driver)
	assert.Equal(t, defaultPrefix, d.cfg.Prefix)
	assert.Equal(t, "bucket-owner-full-control", d.cfg.ObjectCannedACL)
	assert.Equal(t, event.PriorityError, d.RuntimeConfig().MinPriority)
}

func TestSchemaSecrets(t *testing.T) {
	secrets := map[string]bool{}
	for _, f := range OutputType.Schema.Fields {
		secrets[f.Name] = f.Secret
	}
	assert.True(t, secrets["secret_access_key"])
	assert.True(t, secrets["session_token"])
	assert.Contains(t, secrets, "bucket")
	assert.Contains(t, secrets, "runtime.minimum_priority")
	assert.NotContains(t, secrets, "minimum_priority")
}

func TestSendPutsOneObject(t *testing.T) {
	awstest.Isolate(t)
	rec, server := testutil.NewRecorder(t, http.StatusOK, "")
	d := newDriver(t, server.URL, map[string]any{"prefix": "alerts/", "object_canned_acl": "private"})

	evt := testutil.CreateValidEvent()
	require.NoError(t, d.Send(context.Background(), evt))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	req := reqs[0]
	assert.Equal(t, http.MethodPut, req.Method)
	assert.Equal(t, "/"+bucket+"/alerts/2026-04-01/2026-04-01T10:30:00Z_test-uuid-001.json", req.URL.Path)
	assert.Equal(t, "private", req.Header.Get("X-Amz-Acl"))
	assert.Equal(t, contentTypeJSON, req.Header.Get("Content-Type"))
	assert.Contains(t, req.Header.Get("Authorization"), "Credential="+awstest.AccessKeyID+"/")
	assert.Equal(t, awstest.SessionToken, req.Header.Get("X-Amz-Security-Token"))
	want, err := json.Marshal(evt)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(objectBody(t, req)))
}

func TestSendBatchPutsOneNDJSONObject(t *testing.T) {
	awstest.Isolate(t)
	rec, server := testutil.NewRecorder(t, http.StatusOK, "")
	d := newDriver(t, server.URL, nil)

	first := testutil.CreateValidEvent()
	second := testutil.CreateValidEvent()
	second.UUID, second.Rule = "test-uuid-002", "second"
	require.NoError(t, d.(output.BatchSender).SendBatch(context.Background(), []*event.Event{first, second}))
	require.NoError(t, d.(output.BatchSender).SendBatch(context.Background(), nil))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/"+bucket+"/falco/2026-04-01/2026-04-01T10:30:00Z_test-uuid-001.ndjson", reqs[0].URL.Path)
	assert.Equal(t, contentTypeNDJSON, reqs[0].Header.Get("Content-Type"))
	assert.Equal(t, "bucket-owner-full-control", reqs[0].Header.Get("X-Amz-Acl"))
	lines := strings.Split(strings.TrimSuffix(string(objectBody(t, reqs[0])), "\n"), "\n")
	require.Len(t, lines, 2)
	for i, evt := range []*event.Event{first, second} {
		want, err := json.Marshal(evt)
		require.NoError(t, err)
		assert.JSONEq(t, string(want), lines[i])
	}
}

func TestObjectKey(t *testing.T) {
	d := &driver{cfg: config{Prefix: "p"}}
	local := time.FixedZone("CET", 3600)
	evt := &event.Event{Time: time.Date(2026, 1, 1, 0, 30, 0, 123, local), UUID: "u"}
	assert.Equal(t, "p/2025-12-31/2025-12-31T23:30:00.000000123Z_u.json", d.objectKey(evt, ".json"), "date and time are UTC")

	generated := d.objectKey(&event.Event{}, ".json")
	assert.Regexp(t, `^p/\d{4}-\d{2}-\d{2}/[^_]+_[0-9a-f-]{36}\.json$`, generated)
}

// objectBody decodes the aws-chunked encoding the SDK uses to send a trailing checksum.
func objectBody(t *testing.T, req testutil.CapturedRequest) []byte {
	t.Helper()
	if !strings.Contains(req.Header.Get("Content-Encoding"), "aws-chunked") {
		return req.Body
	}
	var out []byte
	rest := req.Body
	for {
		line, after, ok := bytes.Cut(rest, []byte("\r\n"))
		require.True(t, ok, "chunk header")
		var size int
		_, err := fmt.Sscanf(string(bytes.SplitN(line, []byte(";"), 2)[0]), "%x", &size)
		require.NoError(t, err)
		if size == 0 {
			return out
		}
		out = append(out, after[:size]...)
		rest = after[size+2:]
	}
}

func TestPutErrorIsSafe(t *testing.T) {
	awstest.Isolate(t)
	_, server := testutil.NewRecorder(t, http.StatusForbidden,
		`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InvalidAccessKeyId</Code><Message>The AWS Access Key Id you provided does not exist in our records.</Message><AWSAccessKeyId>`+awstest.AccessKeyID+`</AWSAccessKeyId></Error>`)
	d := newDriver(t, server.URL, nil)
	err := d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Equal(t, name+" "+opPutObject+": HTTP 403 Forbidden: InvalidAccessKeyId", err.Error())
	for _, secret := range []string{awstest.AccessKeyID, awstest.SecretAccessKey, awstest.SessionToken} {
		assert.NotContains(t, err.Error(), secret)
	}
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		status       int
		wantErr      bool
		misconfigure bool
	}{
		{name: "bucket exists", status: http.StatusOK},
		{name: "bucket missing", status: http.StatusNotFound, wantErr: true, misconfigure: true},
		{name: "denied", status: http.StatusForbidden, wantErr: true}, // probe needs s3:ListBucket, delivery does not
		{name: "wrong region", status: http.StatusMovedPermanently, wantErr: true, misconfigure: true},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantErr: true},
		{name: "internal error", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			rec, server := testutil.NewRecorder(t, tt.status, tt.body)
			d := newDriver(t, server.URL, nil)
			err := d.HealthCheck(context.Background())
			reqs := rec.Received()
			require.NotEmpty(t, reqs)
			assert.Equal(t, http.MethodHead, reqs[0].Method)
			assert.Equal(t, "/"+bucket, reqs[0].URL.Path)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.misconfigure, errorsIsMisconfigured(err), err.Error())
			assert.Contains(t, err.Error(), name+" "+opHeadBucket)
		})
	}
}

func TestUnreachableIsTransient(t *testing.T) {
	awstest.Isolate(t)
	_, server := testutil.NewRecorder(t, http.StatusOK, "")
	endpoint := server.URL
	server.Close()
	d := newDriver(t, endpoint, nil)
	err := d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.False(t, errorsIsMisconfigured(err))
	assert.Contains(t, err.Error(), "connection refused")
}

func errorsIsMisconfigured(err error) bool {
	return errors.Is(err, output.ErrMisconfigured)
}

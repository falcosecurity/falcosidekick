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

package awssqs

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws/awstest"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	queueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/falco"
	probeOp  = "GetQueueAttributes"
)

type sqsCall struct {
	Body   map[string]any
	Target string
}

// fakeSQS answers the SQS JSON protocol. failIDs lists batch entry ids
// reported as failed; errStatus and errType turn every call into an error.
type fakeSQS struct {
	failIDs   map[string]bool
	errType   string
	calls     []sqsCall
	errStatus int
	mu        sync.Mutex
}

func (f *fakeSQS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	target := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	f.mu.Lock()
	f.calls = append(f.calls, sqsCall{Target: target, Body: body})
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	if f.errStatus != 0 {
		w.WriteHeader(f.errStatus)
		_, _ = io.WriteString(w, `{"__type":"`+f.errType+`","message":"request failed for `+awstest.AccessKeyID+`"}`)
		return
	}
	var reply any
	switch target {
	case "SendMessage":
		reply = map[string]any{"MessageId": "m", "MD5OfMessageBody": digest(body["MessageBody"].(string))}
	case "SendMessageBatch":
		ok, failed := []any{}, []any{}
		for _, e := range body["Entries"].([]any) {
			entry := e.(map[string]any)
			id := entry["Id"].(string)
			if f.failIDs[id] {
				failed = append(failed, map[string]any{"Id": id, "Code": "InvalidMessageContents", "SenderFault": true})
				continue
			}
			ok = append(ok, map[string]any{"Id": id, "MessageId": "m" + id, "MD5OfMessageBody": digest(entry["MessageBody"].(string))})
		}
		reply = map[string]any{"Successful": ok, "Failed": failed}
	case probeOp:
		reply = map[string]any{"Attributes": map[string]string{"QueueArn": "arn:aws:sqs:eu-west-1:123456789012:falco"}}
	}
	_ = json.NewEncoder(w).Encode(reply)
}

func (f *fakeSQS) received() []sqsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sqsCall(nil), f.calls...)
}

func digest(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func startFake(t *testing.T, f *fakeSQS) string {
	t.Helper()
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	return server.URL
}

func newDriver(t *testing.T, endpoint string, extra map[string]any) output.Driver {
	t.Helper()
	cfg := awstest.Config(endpoint, map[string]any{"queue_url": queueURL})
	maps.Copy(cfg, extra)
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
		{name: "minimal, region from the queue url", cfg: map[string]any{"queue_url": queueURL}},
		{name: "missing queue url", cfg: map[string]any{}, wantErr: "queue_url: is required"},
		{name: "relative queue url", cfg: map[string]any{"queue_url": "123456789012/falco"}, wantErr: "queue_url: must be an http or https URL"},
		{name: "no region anywhere", cfg: map[string]any{"queue_url": "http://localhost:4566/000000000000/falco"}, wantErr: "region: is required"},
		{name: "shared aws validation", cfg: map[string]any{"queue_url": queueURL, "role_arn": "x"}, wantErr: "role_arn: must be an IAM role ARN"},
		{name: "unknown key", cfg: map[string]any{"queue_url": queueURL, "url": "x"}, wantErr: "unknown keys: url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
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

func TestQueueRegion(t *testing.T) {
	tests := map[string]string{
		"https://sqs.us-east-2.amazonaws.com/1/q":                     "us-east-2",
		"https://sqs.cn-north-1.amazonaws.com.cn/1/q":                 "cn-north-1",
		"https://eu-west-1.queue.amazonaws.com/1/q":                   "eu-west-1",
		"http://sqs.eu-central-1.localhost.localstack.cloud:4566/1/q": "eu-central-1",
		"http://localhost:4566/000000000000/q":                        "",
		"http://[::1":                                                 "",
	}
	for queue, want := range tests {
		assert.Equal(t, want, queueRegion(queue), queue)
	}
}

func TestSendMessage(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSQS{}
	d := newDriver(t, startFake(t, fake), map[string]any{"runtime": map[string]any{"minimum_priority": "warning"}})
	assert.Equal(t, event.PriorityWarning, d.RuntimeConfig().MinPriority)

	evt := testutil.CreateValidEvent()
	require.NoError(t, d.Send(context.Background(), evt))
	calls := fake.received()
	require.Len(t, calls, 1)
	assert.Equal(t, "SendMessage", calls[0].Target)
	assert.Equal(t, queueURL, calls[0].Body["QueueUrl"])
	assert.NotContains(t, calls[0].Body, "MessageAttributes")
	want, err := json.Marshal(evt)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), calls[0].Body["MessageBody"].(string))
}

func TestSendBatchSplitsByEntries(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSQS{}
	d := newDriver(t, startFake(t, fake), nil)
	events := make([]*event.Event, 23)
	for i := range events {
		events[i] = testutil.CreateValidEvent()
	}
	require.NoError(t, d.(output.BatchSender).SendBatch(context.Background(), events))
	calls := fake.received()
	require.Len(t, calls, 3)
	for i, want := range []int{10, 10, 3} {
		assert.Equal(t, "SendMessageBatch", calls[i].Target)
		assert.Len(t, calls[i].Body["Entries"], want)
	}
}

func TestSplitBatch(t *testing.T) {
	big := strings.Repeat("x", 400*1024)
	huge := strings.Repeat("y", maxBatchBytes+1)
	small := "s"
	sizes := func(chunks [][]string) []int {
		n := make([]int, 0, len(chunks))
		for _, c := range chunks {
			n = append(n, len(c))
		}
		return n
	}
	assert.Equal(t, []int{2, 1}, sizes(splitBatch([]string{big, big, big})), "1 MiB per request")
	assert.Equal(t, []int{1, 1, 1}, sizes(splitBatch([]string{small, huge, small})), "an oversized body goes alone")
	assert.Equal(t, []int{10, 1}, sizes(splitBatch(make([]string, 11))))
	assert.Empty(t, splitBatch(nil))
}

func TestSendBatchPartialFailure(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSQS{failIDs: map[string]bool{"1": true, "3": true}}
	d := newDriver(t, startFake(t, fake), nil)
	events := make([]*event.Event, 12)
	for i := range events {
		events[i] = testutil.CreateValidEvent()
	}
	err := d.(output.BatchSender).SendBatch(context.Background(), events)
	require.Error(t, err)
	assert.Equal(t, "awssqs SendMessageBatch: 3/12 entries failed (InvalidMessageContents)", err.Error())
	assert.Len(t, fake.received(), 2, "every request is sent")
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name         string
		errType      string
		status       int
		misconfigure bool
		denied       bool // transient for the probe only
	}{
		{name: "queue missing", status: 400, errType: "QueueDoesNotExist", misconfigure: true},
		{name: "invalid token", status: 403, errType: "InvalidClientTokenId", misconfigure: true},
		{name: "denied", status: 400, errType: "AccessDenied", misconfigure: true, denied: true},
		{name: "throttled", status: 400, errType: "ThrottlingException"},
		{name: "internal", status: 500, errType: "InternalError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			fake := &fakeSQS{errStatus: tt.status, errType: tt.errType}
			d := newDriver(t, startFake(t, fake), nil)
			calls := map[string]error{
				probeOp:            d.HealthCheck(context.Background()),
				"SendMessage":      d.Send(context.Background(), testutil.CreateValidEvent()),
				"SendMessageBatch": d.(output.BatchSender).SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent()}),
			}
			for op, err := range calls {
				require.Error(t, err, op)
				want := tt.misconfigure && (!tt.denied || op != probeOp)
				assert.Equal(t, want, errors.Is(err, output.ErrMisconfigured), err.Error())
				assert.Contains(t, err.Error(), "awssqs "+op+": "+tt.errType)
				for _, secret := range []string{awstest.AccessKeyID, awstest.SecretAccessKey, awstest.SessionToken} {
					assert.NotContains(t, err.Error(), secret)
				}
			}
		})
	}
}

func TestHealthCheck(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSQS{}
	d := newDriver(t, startFake(t, fake), nil)
	require.NoError(t, d.HealthCheck(context.Background()))
	calls := fake.received()
	require.Len(t, calls, 1)
	assert.Equal(t, probeOp, calls[0].Target)
	assert.Equal(t, []any{"QueueArn"}, calls[0].Body["AttributeNames"])
}

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

package awssns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

const topicARN = "arn:aws:sns:eu-central-1:123456789012:falco"

// fakeSNS answers the SNS query protocol.
type fakeSNS struct {
	errCode   string
	forms     []url.Values
	errStatus int
	mu        sync.Mutex
}

func (f *fakeSNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	if f.errStatus != 0 {
		w.WriteHeader(f.errStatus)
		_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>failed for %s</Message></Error><RequestId>r</RequestId></ErrorResponse>`,
			f.errCode, awstest.AccessKeyID)
		return
	}
	action := r.PostForm.Get("Action")
	switch action {
	case opPublish:
		_, _ = fmt.Fprint(w, `<PublishResponse><PublishResult><MessageId>m</MessageId></PublishResult></PublishResponse>`)
	case opGetTopicAttributes:
		_, _ = fmt.Fprint(w, `<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes/></GetTopicAttributesResult></GetTopicAttributesResponse>`)
	}
}

func (f *fakeSNS) received() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.forms...)
}

func newDriver(t *testing.T, f *fakeSNS, extra map[string]any) output.Driver {
	t.Helper()
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	return newDriverAt(t, server.URL, extra)
}

func newDriverAt(t *testing.T, endpoint string, extra map[string]any) output.Driver {
	t.Helper()
	cfg := awstest.Config(endpoint, map[string]any{"topic_arn": topicARN})
	maps.Copy(cfg, extra)
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func attributes(form url.Values) map[string][2]string {
	attrs := map[string][2]string{}
	for i := 1; ; i++ {
		prefix := fmt.Sprintf("MessageAttributes.entry.%d.", i)
		name := form.Get(prefix + "Name")
		if name == "" {
			return attrs
		}
		attrs[name] = [2]string{form.Get(prefix + "Value.DataType"), form.Get(prefix + "Value.StringValue")}
	}
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr string
	}{
		{name: "minimal, region from the topic arn", cfg: map[string]any{"topic_arn": topicARN}},
		{name: "text", cfg: map[string]any{"topic_arn": topicARN, "format": "text"}},
		{name: "json", cfg: map[string]any{"topic_arn": topicARN, "format": "json"}},
		{name: "unknown format", cfg: map[string]any{"topic_arn": topicARN, "format": "xml"}, wantErr: "format: must be json/text"},
		{name: "raw_json is refused", cfg: map[string]any{"topic_arn": topicARN, "raw_json": true}, wantErr: "unknown keys: raw_json"},
		{name: "missing topic", cfg: map[string]any{}, wantErr: "topic_arn: is required"},
		{name: "not an arn", cfg: map[string]any{"topic_arn": "falco"}, wantErr: "topic_arn: must be an SNS topic ARN"},
		{name: "arn of another service", cfg: map[string]any{"topic_arn": "arn:aws:sqs:eu-west-1:123456789012:falco"}, wantErr: "topic_arn: must be an SNS topic ARN"},
		{name: "unknown v2 key", cfg: map[string]any{"topic_arn": topicARN, "rawjson": true}, wantErr: "unknown keys: rawjson"},
		{name: "fifo topic", cfg: map[string]any{"topic_arn": topicARN + ".fifo"}, wantErr: "topic_arn: FIFO topics are not supported"},
		{name: "shared aws validation", cfg: map[string]any{"topic_arn": topicARN, "external_id": "x1"}, wantErr: "external_id: requires role_arn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			d, err := OutputType.New(tt.cfg, output.Deps{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, name, d.Name())
				assert.Equal(t, "eu-central-1", d.(*driver).client.Options().Region)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestPublishAttributes(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSNS{}
	d := newDriver(t, fake, map[string]any{
		"format":  "text",
		"runtime": map[string]any{"minimum_priority": "error"},
		"message_attributes": []any{"priority", "rule", "source", "tags", "hostname",
			"proc.aname[2]", "evt.num", "fd.num", "proc.pid", "thread.tid"},
	})
	assert.Equal(t, event.PriorityError, d.RuntimeConfig().MinPriority)

	evt := testutil.CreateValidEvent()
	evt.OutputFields = map[string]any{
		"proc.aname[2]": "bash",
		"evt.num":       json.Number("42"),
		"fd.num":        float64(3),
		"proc.pid":      int64(7),
		"thread.tid":    8,
		"proc.name":     "not listed",
		"priority":      "an output field does not replace the event priority",
	}
	require.NoError(t, d.Send(context.Background(), evt))
	forms := fake.received()
	require.Len(t, forms, 1)
	form := forms[0]
	assert.Equal(t, opPublish, form.Get("Action"))
	assert.Equal(t, topicARN, form.Get("TopicArn"))
	assert.Equal(t, evt.Output, form.Get("Message"))
	assert.Equal(t, map[string][2]string{
		"priority":     {"String", "Error"},
		"rule":         {"String", evt.Rule},
		"source":       {"String", "syscall"},
		"tags":         {"String", "filesystem,mitre_persistence"},
		"hostname":     {"String", "node-1"},
		"proc.aname.2": {"String", "bash"},
		"evt.num":      {"Number", "42"},
		"fd.num":       {"Number", "3"},
		"proc.pid":     {"Number", "7"},
		"thread.tid":   {"Number", "8"},
	}, attributes(form))
}

// D5: by default only the five event attributes; listed output fields are sent only when the event has them.
func TestMessageAttributesDefaultAndValidation(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSNS{}
	d := newDriver(t, fake, nil)
	evt := testutil.CreateValidEvent()
	evt.OutputFields = map[string]any{"proc.name": "bash", "empty": "", "list": []any{"x"}}
	require.NoError(t, d.Send(context.Background(), evt))
	assert.Equal(t, []string{"hostname", "priority", "rule", "source", "tags"}, slices.Sorted(maps.Keys(attributes(fake.received()[0]))))

	listed := &driver{cfg: config{TopicARN: topicARN, MessageAttributes: []string{"proc.name", "empty", "list", "missing"}}}
	input, err := listed.publishInput(evt)
	require.NoError(t, err)
	assert.Equal(t, []string{"proc.name"}, slices.Sorted(maps.Keys(input.MessageAttributes)))

	for _, tc := range []struct {
		want  string
		names []any
	}{
		{names: []any{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}, want: "message_attributes: at most 10"},
		{names: []any{"proc.aname[2]", "proc.aname.2"}, want: `"proc.aname[2]" and "proc.aname.2" are the same attribute`},
		{names: []any{"rule", "rule"}, want: `"rule" and "rule" are the same attribute`},
		{names: []any{"aws.reserved"}, want: `"aws.reserved" is not a valid SNS attribute name`},
		{names: []any{"container.label[app.kubernetes.io/x]"}, want: "is not a valid SNS attribute name"},
	} {
		_, err := OutputType.New(map[string]any{"topic_arn": topicARN, "message_attributes": tc.names}, output.Deps{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.want)
	}
	_, err = OutputType.New(map[string]any{"topic_arn": topicARN, "message_attributes": []any{}}, output.Deps{})
	assert.NoError(t, err, "an empty list sends no attributes")
}

func TestPublishWithoutOutputUsesRule(t *testing.T) {
	d := &driver{cfg: config{TopicARN: topicARN, Format: formatText}}
	evt := testutil.CreateValidEvent()
	evt.Output, evt.Tags, evt.Hostname = "", nil, ""
	input, err := d.publishInput(evt)
	require.NoError(t, err)
	assert.Equal(t, evt.Rule, *input.Message)
	assert.NotContains(t, input.MessageAttributes, "tags")
	assert.NotContains(t, input.MessageAttributes, "hostname")
}

// The event JSON is the default body, and the message attributes go with it.
func TestPublishJSONByDefault(t *testing.T) {
	for _, extra := range []map[string]any{nil, {"format": "json"}} {
		awstest.Isolate(t)
		fake := &fakeSNS{}
		d := newDriver(t, fake, extra)
		evt := testutil.CreateValidEvent()
		require.NoError(t, d.Send(context.Background(), evt))
		form := fake.received()[0]
		want, err := json.Marshal(evt)
		require.NoError(t, err)
		assert.JSONEq(t, string(want), form.Get("Message"))
		assert.Contains(t, form.Get("Message"), `"priority":"Error"`, "Falco's casing")
		assert.Equal(t, map[string][2]string{
			"priority": {"String", "Error"},
			"rule":     {"String", evt.Rule},
			"source":   {"String", "syscall"},
			"tags":     {"String", "filesystem,mitre_persistence"},
			"hostname": {"String", "node-1"},
		}, attributes(form))
	}
	i := slices.IndexFunc(OutputType.Schema.Fields, func(f output.SchemaField) bool { return f.Name == "format" })
	require.GreaterOrEqual(t, i, 0)
	assert.Equal(t, "json", OutputType.Schema.Fields[i].Default)
}

func TestNumberType(t *testing.T) {
	tests := map[string]string{
		"42": "Number", "-1000000000": "Number", "0.12345": "Number", "3.5": "Number",
		"1000000001": "String", "1735689600000000000": "String", "0.123456": "String",
		"1e3": "String", "NaN": "String", "x": "String",
	}
	for value, want := range tests {
		assert.Equal(t, want, numberType(value), value)
	}
}

func TestAttributeNames(t *testing.T) {
	valid := []string{"a", "proc.name", "k8s-ns_name", strings.Repeat("a", 256)}
	invalid := []string{"", ".a", "a.", "a..b", "a/b", "AWS.x", "amazon.y", strings.Repeat("a", 257)}
	for _, n := range valid {
		assert.True(t, validAttributeName(n), n)
	}
	for _, n := range invalid {
		assert.False(t, validAttributeName(n), n)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		want         string
		status       int
		misconfigure bool
		denied       bool // transient for the probe only
	}{
		{name: "topic missing", status: 404, code: "NotFound", want: "HTTP 404 Not Found: NotFoundException", misconfigure: true},
		{name: "authorization", status: 403, code: "AuthorizationError", want: "HTTP 403 Forbidden: AuthorizationErrorException", misconfigure: true, denied: true},
		{name: "invalid token", status: 403, code: "InvalidClientTokenId", want: "HTTP 403 Forbidden: InvalidClientTokenId", misconfigure: true},
		{name: "throttled", status: 400, code: "Throttling", want: "HTTP 400 Bad Request: Throttling"},
		{name: "internal", status: 500, code: "InternalError", want: "HTTP 500 Internal Server Error: InternalErrorException"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			d := newDriver(t, &fakeSNS{errStatus: tt.status, errCode: tt.code}, nil)
			for op, err := range map[string]error{
				opGetTopicAttributes: d.HealthCheck(context.Background()),
				opPublish:            d.Send(context.Background(), testutil.CreateValidEvent()),
			} {
				require.Error(t, err, op)
				want := tt.misconfigure && (!tt.denied || op != opGetTopicAttributes)
				assert.Equal(t, want, errors.Is(err, output.ErrMisconfigured), err.Error())
				assert.Equal(t, name+" "+op+": "+tt.want, err.Error())
				for _, secret := range []string{awstest.AccessKeyID, awstest.SecretAccessKey, awstest.SessionToken} {
					assert.NotContains(t, err.Error(), secret)
				}
			}
		})
	}
}

func TestHealthCheck(t *testing.T) {
	awstest.Isolate(t)
	fake := &fakeSNS{}
	d := newDriver(t, fake, nil)
	require.NoError(t, d.HealthCheck(context.Background()))
	form := fake.received()[0]
	assert.Equal(t, opGetTopicAttributes, form.Get("Action"))
	assert.Equal(t, topicARN, form.Get("TopicArn"))
}

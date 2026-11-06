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

//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoed is the value every case submits or every fake destination answers with;
// no diagnostic may repeat it.
const echoed = "S3NT1NEL-e2e"

// outputYAML renders one output entry; every "$V" in body becomes the echoed value.
func outputYAML(name, body string) string {
	lines := strings.Split(strings.ReplaceAll(body, "$V", echoed), "\n")
	return name + ":\n  " + strings.Join(lines, "\n  ") + "\n"
}

func withExtra(extra string) coreOptions {
	opts := defaultCore
	opts.extra = extra
	return opts
}

func TestInvalidConfigIsRejectedWithoutEchoingValues(t *testing.T) {
	webhook := outputYAML("webhook", "host: http://127.0.0.1:1")
	kafka := "brokers: [127.0.0.1:1]\ntopic: t\n"
	for _, tc := range []struct {
		core    coreOptions
		name    string
		outputs string
		want    string
	}{
		{name: "log_level", core: coreOptions{logLevel: echoed, logFormat: "json"}, outputs: webhook,
			want: "log_level: must be trace/debug/info/warning/error"},
		{name: "log_format", core: coreOptions{logLevel: "info", logFormat: echoed}, outputs: webhook,
			want: "log_format: must be text/json"},
		{name: "database backend", core: withExtra("database:\n  backend: " + echoed + "\n"), outputs: webhook,
			want: "backend: must be inmemory/sqlite/postgres"},
		{name: "ui event_source", core: withExtra("ui:\n  enabled: true\n  event_source: " + echoed + "\n"), outputs: webhook,
			want: "ui.event_source: output not found or does not implement ReadableStore"},
		{name: "minimum_priority", outputs: outputYAML("webhook", "host: http://127.0.0.1:1\nruntime:\n  minimum_priority: $V"),
			want: "minimum_priority: must be a Falco priority"},
		{name: "webhook method", outputs: outputYAML("webhook", "host: http://127.0.0.1:1\nmethod: $V"),
			want: "method: must be POST or PUT"},
		{name: "tls ca_file", outputs: outputYAML("webhook", "host: https://127.0.0.1:1\ntls:\n  ca_file: /nonexistent-$V/ca.pem"),
			want: "ca_file: file does not exist"},
		{name: "loki log_format", outputs: outputYAML("loki", "host: http://127.0.0.1:1\nlog_format: $V"),
			want: "log_format: must be json/text"},
		{name: "slack output_format", outputs: outputYAML("slack", "secret_endpoint: /hook\noutput_format: $V"),
			want: "output_format: must be all/fields/text"},
		{name: "slack message_format", outputs: outputYAML("slack", "secret_endpoint: /hook\nmessage_format: \"{{ .$V \""),
			want: "message_format: invalid Go template"},
		{name: "teams output_format", outputs: outputYAML("teams", "host: http://127.0.0.1:1\nsecret_endpoint: /hook\noutput_format: $V"),
			want: "output_format: must be all/text/fields"},
		{name: "datadog site", outputs: outputYAML("datadog", "api_key: k\nsite: $V"), want: "site: must be one of"},
		{name: "opsgenie region", outputs: outputYAML("opsgenie", "api_key: k\nregion: $V"), want: "region: must be us/eu"},
		{name: "pagerduty region", outputs: outputYAML("pagerduty", "routing_key: k\nregion: $V"), want: "region: must be us/eu"},
		{name: "elasticsearch index", outputs: outputYAML("elasticsearch", "host: http://127.0.0.1:1\nindex: $V"),
			want: "index: must be lowercase alphanumeric"},
		{name: "elasticsearch index_suffix", outputs: outputYAML("elasticsearch", "host: http://127.0.0.1:1\nindex_suffix: $V"),
			want: "index_suffix: must be daily/monthly/annually/none"},
		{name: "syslog protocol", outputs: outputYAML("syslog", "host: 127.0.0.1\nprotocol: $V"), want: "protocol: must be tcp/udp/tls"},
		{name: "syslog format", outputs: outputYAML("syslog", "host: 127.0.0.1\nformat: $V"), want: "format: must be json/cef"},
		{name: "redis storage_type", outputs: outputYAML("redis", "address: 127.0.0.1:1\nstorage_type: $V"),
			want: "storage_type: must be list/hashmap/stream"},
		{name: "smtp tls_mode", outputs: outputYAML("smtp", "host: 127.0.0.1\ntls_mode: $V"),
			want: "tls_mode: must be starttls/implicit/opportunistic/none"},
		{name: "smtp auth_mechanism", outputs: outputYAML("smtp", "host: 127.0.0.1\nauth_mechanism: $V"),
			want: "auth_mechanism: must be plain/xoauth2/none"},
		{name: "smtp output_format", outputs: outputYAML("smtp", "host: 127.0.0.1\noutput_format: $V"),
			want: "output_format: must be html/text"},
		{name: "kafka sasl", outputs: outputYAML("kafka", kafka+"auth:\n  sasl: $V"),
			want: "sasl: must be plain/scram_sha256/scram_sha512"},
		{name: "kafka compression", outputs: outputYAML("kafka", kafka+"producer:\n  compression: $V"),
			want: "compression: must be none/gzip/snappy/lz4/zstd"},
		{name: "kafka balancer", outputs: outputYAML("kafka", kafka+"producer:\n  balancer: $V"),
			want: "balancer: must be round_robin/least_backup/sticky"},
		{name: "kafka required_acks", outputs: outputYAML("kafka", kafka+"producer:\n  required_acks: $V"),
			want: "required_acks: must be all/one/none"},
		{name: "otlp protocol", outputs: outputYAML("otlp", "logs:\n  endpoint: http://127.0.0.1:1\n  protocol: $V"),
			want: "protocol: must be grpc or http/protobuf"},
		{name: "otlp compression", outputs: outputYAML("otlp", "logs:\n  endpoint: http://127.0.0.1:1\n  compression: $V"),
			want: "compression: must be none or gzip"},
		{name: "awss3 bucket", outputs: outputYAML("awss3", "region: us-east-1\nbucket: $V"), want: "bucket: invalid bucket name"},
		{name: "awss3 object_canned_acl", outputs: outputYAML("awss3", "region: us-east-1\nbucket: fsk-e2e\nobject_canned_acl: $V"),
			want: "object_canned_acl: must be one of"},
		{name: "aws region", outputs: outputYAML("awssqs", "region: $V\nqueue_url: https://sqs.us-east-1.amazonaws.com/000000000000/q"),
			want: "region: invalid region"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			core := tc.core
			if core.logLevel == "" {
				core = defaultCore
			}
			logs := startSidekickFailsWith(t, core, tc.outputs)
			assert.Contains(t, logs, tc.want)
			assert.NotContains(t, logs, echoed)
		})
	}
}

func TestAPIAnswersNeverEchoInput(t *testing.T) {
	core := withExtra("api:\n  allow_writes: true\nui:\n  enabled: true\n  event_source: inmemory\n")
	sk := startSidekickWith(t, core, outputYAML("inmemory", "capacity: 100"))

	const (
		outputPath = "/api/v1/pipeline/outputs/webhook"
		searchPath = "/api/v1/events/search?"
		event      = `{"rule":"r","time":"2026-11-06T10:00:00Z","priority":"$V","output_fields":{"a":"b"}}`
	)
	for _, tc := range []struct {
		name, method, path, body, want string
	}{
		{name: "event JSON", method: http.MethodPost, path: "/", body: `{"rule": "$V`, want: "invalid JSON"},
		{name: "event priority", method: http.MethodPost, path: "/", body: event, want: "unknown priority"},
		{name: "output JSON", method: http.MethodPut, path: outputPath, body: `{"config": "$V`, want: "invalid JSON"},
		{name: "output method", method: http.MethodPut, path: outputPath,
			body: `{"config":{"host":"http://127.0.0.1:1","method":"$V"}}`, want: "method: must be POST or PUT"},
		{name: "output ca_file", method: http.MethodPut, path: outputPath,
			body: `{"config":{"host":"https://127.0.0.1:1","tls":{"ca_file":"/nonexistent-$V/ca.pem"}}}`, want: "ca_file: file does not exist"},
		{name: "layout JSON", method: http.MethodPut, path: "/api/v1/pipeline/layout", body: `{"$V`, want: "invalid JSON"},
		{name: "search page", method: http.MethodGet, path: searchPath + "page=$V", want: "page must be an integer"},
		{name: "search limit", method: http.MethodGet, path: searchPath + "limit=$V", want: "limit must be an integer"},
		{name: "search since", method: http.MethodGet, path: searchPath + "since=$V", want: "since must be a non-negative duration"},
		{name: "search sort_by", method: http.MethodGet, path: searchPath + "sort_by=$V", want: "sort_by must be timestamp/priority/rule/source"},
		{name: "search sort_desc", method: http.MethodGet, path: searchPath + "sort_desc=$V", want: "sort_desc must be a boolean"},
		{name: "count group_by", method: http.MethodGet, path: "/api/v1/events/count/$V", want: "group_by must be priority/rule/source/tags/hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.body != "" {
				body = []byte(strings.ReplaceAll(tc.body, "$V", echoed))
			}
			resp, err := httpDo(tc.method, sk.url+strings.ReplaceAll(tc.path, "$V", echoed), body)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			answer, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, string(answer))
			assert.Contains(t, string(answer), tc.want)
			assert.NotContains(t, string(answer), echoed)
		})
	}
	assert.NotContains(t, sk.logs.String(), echoed)
}

// hostileDestination answers every request with status and the echoed value
// in the body and in the headers, as a destination that reflects input or leaks internals would.
func hostileDestination(t *testing.T, status int) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-Id", echoed)
		w.Header().Set("WWW-Authenticate", `Bearer error="`+echoed+`"`)
		w.Header().Set("Content-Type", "application/json")
		if status >= 300 && status < 400 {
			w.Header().Set("Location", "http://127.0.0.2:1/"+echoed+"?token="+url.QueryEscape(echoed))
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":%[1]q,"message":%[1]q,"errors":true,`+
			`"items":[{"create":{"status":400,"error":{"type":%[1]q,"reason":%[1]q}}}]}`, echoed)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// hostileOutputs configures every HTTP output against host with the startup probe off,
// so every request is a delivery.
func hostileOutputs(host string) (outputs string, names []string) {
	defs := []struct{ name, body string }{
		{"webhook", "host: %q"},
		{"slack", "host: %q\nsecret_endpoint: /hook"},
		{"loki", "host: %q"},
		{"alertmanager", "hosts: [%q]"},
		{"discord", "host: %q\nsecret_endpoint: /hook"},
		{"teams", "host: %q\nsecret_endpoint: /hook"},
		{"cloudevents", "host: %q\nsecret_endpoint: /hook"},
		{"datadog", "host: %q\napi_key: k"},
		{"grafanaoncall", "host: %q\nsecret_endpoint: /hook"},
		{"opsgenie", "host: %q\napi_key: k"},
		{"pagerduty", "host: %q\nrouting_key: k"},
		{"talon", "host: %q"},
		{"elasticsearch", "host: %q"},
		{"otlp", "logs:\n  endpoint: %q\n  timeout: 2s"},
	}
	for _, d := range defs {
		outputs += outputYAML(d.name, fmt.Sprintf(d.body, host)+"\nruntime:\n  health_check: false")
		names = append(names, d.name)
	}
	return outputs, names
}

func TestHostileDestinationsNeverReachDiagnostics(t *testing.T) {
	modes := []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError,
		http.StatusOK, http.StatusTemporaryRedirect,
	}
	for _, status := range modes {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			outputs, names := hostileOutputs(hostileDestination(t, status))
			sk := startSidekick(t, outputs)
			sk.postEvent(t, newMarker(t))
			for _, name := range names {
				st := sk.waitStatus(t, name, func(st outputStatus) bool { return st.SentTotal+st.FailedTotal >= 1 })
				if status != http.StatusOK {
					assert.Equal(t, 1, st.FailedTotal, "%s must take the failure path", name)
					assert.NotEmpty(t, st.LastError, name)
				}
			}
			for _, path := range []string{"/api/v1/pipeline/status", "/api/v1/pipeline"} {
				resp, err := httpDo(http.MethodGet, sk.url+path, nil)
				require.NoError(t, err)
				answer, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				require.NoError(t, err)
				assert.NotContains(t, string(answer), echoed, path)
			}
			assert.NotContains(t, sk.logs.String(), echoed)
		})
	}
}

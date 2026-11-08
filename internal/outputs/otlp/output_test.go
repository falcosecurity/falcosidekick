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

package otlp

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc/codes"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	secret     = "s3cr3t-otlp-token"
	secondUUID = "test-uuid-002"
)

func newDriver(t *testing.T, raw map[string]any) *driver {
	t.Helper()
	drv, err := OutputType.New(raw, output.Deps{})
	require.NoError(t, err)
	d := drv.(*driver)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func allSignals(endpoint, protocol string, extra map[string]any) map[string]any {
	raw := map[string]any{}
	for _, s := range []string{"logs", "metrics"} {
		section := map[string]any{"endpoint": endpoint, "protocol": protocol}
		for k, v := range extra {
			section[k] = v
		}
		raw[s] = section
	}
	return raw
}

func TestConfigValidation(t *testing.T) {
	logs := func(section map[string]any) map[string]any { return map[string]any{"logs": section} }
	tests := []struct {
		raw  map[string]any
		name string
		want string
	}{
		{name: "no signal", raw: map[string]any{}, want: "at least one of logs or metrics is required"},
		{name: "traces is gone", raw: map[string]any{"traces": map[string]any{"endpoint": "http://c:4318"}}, want: "unknown keys: traces"},
		{name: "traces beside logs", raw: map[string]any{
			"logs": map[string]any{"endpoint": "http://c:4318"}, "traces": map[string]any{"endpoint": "http://c:4318"},
		}, want: "unknown keys: traces"},
		{name: "missing endpoint", raw: logs(map[string]any{"protocol": "grpc"}), want: "logs.endpoint: is required"},
		{name: "bad scheme", raw: logs(map[string]any{"endpoint": "ftp://c:4318"}), want: "must be an http or https URL"},
		{name: "no host", raw: logs(map[string]any{"endpoint": "http://"}), want: "must be an http or https URL"},
		{name: "invalid url", raw: logs(map[string]any{"endpoint": "http://c:4318/%zz"}), want: "invalid URL"},
		{name: "credentials", raw: logs(map[string]any{"endpoint": "https://user:" + secret + "@c:4318"}), want: "must not include credentials"},
		{name: "query", raw: logs(map[string]any{"endpoint": "http://c:4318/v1/logs?token=" + secret}), want: "must not include a query"},
		{name: "grpc path", raw: logs(map[string]any{"endpoint": "http://c:4317/v1/logs", "protocol": "grpc"}), want: "must not include a path"},
		{name: "tls on http", raw: logs(map[string]any{"endpoint": "http://c:4318", "tls": map[string]any{"server_name": "c"}}), want: "tls settings require an https endpoint"},
		{name: "protocol", raw: map[string]any{"logs": map[string]any{"endpoint": "http://c:4318", "protocol": "http/json"}}, want: "logs.protocol"},
		{name: "compression", raw: map[string]any{"logs": map[string]any{"endpoint": "http://c:4318", "compression": "zstd"}}, want: "logs.compression"},
		{name: "timeout", raw: logs(map[string]any{"endpoint": "http://c:4318", "timeout": "-1s"}), want: "logs.timeout: must be positive"},
		{name: "authorization value", raw: logs(map[string]any{"endpoint": "http://c:4318", "headers": map[string]any{
			"Authorization": map[string]any{"values": []string{"Bearer " + secret}},
		}}), want: "authorization must use secrets or files"},
		{name: "transport header", raw: logs(map[string]any{"endpoint": "http://c:4318", "headers": map[string]any{
			"Content-Encoding": map[string]any{"values": []string{"gzip"}},
		}}), want: "owned by the HTTP transport"},
		{name: "header file missing", raw: logs(map[string]any{"endpoint": "http://c:4318", "headers": map[string]any{
			"X-Token": map[string]any{"files": []string{"/nonexistent/" + secret}},
		}}), want: "files[0]: file does not exist"},
		{name: "empty extra attribute", raw: map[string]any{"metrics": map[string]any{"endpoint": "http://c:4318", "extra_attributes": []string{" "}}}, want: "metrics.extra_attributes[0]"},
		{name: "reserved extra attribute", raw: map[string]any{"metrics": map[string]any{"endpoint": "http://c:4318", "extra_attributes": []string{"falco.rule"}}}, want: "set on every data point"},
		{name: "duplicate extra attribute", raw: map[string]any{"metrics": map[string]any{"endpoint": "http://c:4318", "extra_attributes": []string{"k8s.pod.name", "k8s.pod.name"}}}, want: "duplicate field"},
		{name: "unknown key", raw: logs(map[string]any{"endpoint": "http://c:4318", "extraenvvars": map[string]any{}}), want: "unknown keys"},
		{name: "span duration is gone", raw: logs(map[string]any{"endpoint": "http://c:4318", "duration": "1s"}), want: "unknown keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OutputType.New(tt.raw, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, err.Error(), secret)
		})
	}
}

func TestDefaultsAndSchema(t *testing.T) {
	d := newDriver(t, map[string]any{
		"logs":    map[string]any{"endpoint": "http://c:4318"},
		"runtime": map[string]any{"minimum_priority": "notice"},
	})
	assert.Equal(t, protocolHTTP, d.cfg.Logs.Protocol)
	assert.Equal(t, compressionNone, d.cfg.Logs.Compression)
	assert.Equal(t, defaultTimeout, d.cfg.Logs.Timeout)
	assert.Nil(t, d.cfg.Metrics)
	assert.Equal(t, "otlp", d.Name())
	assert.Equal(t, event.PriorityNotice, d.RuntimeConfig().MinPriority)
	require.Len(t, d.signals, 1)
	assert.NoError(t, d.HealthCheck(context.Background()))

	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	for _, s := range []string{"logs", "metrics"} {
		for _, key := range []string{"endpoint", "protocol", "compression", "timeout", "headers", "tls.ca_file"} {
			assert.Contains(t, fields, s+"."+key)
		}
		var secretEntry bool
		for _, entry := range fields[s+".headers"].EntryFields {
			secretEntry = secretEntry || (entry.Name == "secrets" && entry.Secret)
		}
		assert.True(t, secretEntry, "%s header secrets are schema secrets", s)
	}
	assert.Contains(t, fields, "metrics.extra_attributes")
	for name := range fields {
		assert.False(t, strings.HasPrefix(name, "traces."), "no traces signal: %s", name)
	}
	assert.NotContains(t, fields, "logs.duration")
}

func TestTargetPaths(t *testing.T) {
	tests := []struct {
		endpoint, want string
		secure         bool
	}{
		{endpoint: "http://c:4318", want: "/v1/logs"},
		{endpoint: "http://c:4318/", want: "/v1/logs"},
		{endpoint: "https://c/otlp/v1/logs", want: "/otlp/v1/logs", secure: true},
	}
	for _, tt := range tests {
		cfg := signalConfig{Endpoint: tt.endpoint}
		got := cfg.target("/v1/logs")
		assert.Equal(t, tt.want, got.path, tt.endpoint)
		assert.Equal(t, tt.secure, got.secure, tt.endpoint)
	}
}

func TestDeliversEverySignal(t *testing.T) {
	receivers := map[string]func(t *testing.T) (*receiver, string){
		protocolHTTP: startHTTPReceiver,
		protocolGRPC: startGRPCReceiver,
	}
	for protocol, start := range receivers {
		for _, compression := range []string{compressionNone, compressionGzip} {
			t.Run(protocol+"/"+compression, func(t *testing.T) {
				r, endpoint := start(t)
				raw := allSignals(endpoint, protocol, map[string]any{
					"compression": compression,
					"headers": map[string]any{
						"X-Team":  map[string]any{"values": []string{"security"}},
						"X-Token": map[string]any{"secrets": []string{secret}},
					},
				})
				d := newDriver(t, raw)

				evt := testutil.CreateValidEvent()
				require.NoError(t, d.Send(context.Background(), evt))

				got := r.snapshot()
				require.Len(t, got.logs, 1)
				require.Len(t, got.metrics, 1)
				for i, h := range got.headers {
					assert.Equal(t, "security", h["x-team"])
					assert.Equal(t, secret, h["x-token"])
					if protocol == protocolHTTP {
						assert.Equal(t, map[string]string{compressionNone: "", compressionGzip: "gzip"}[compression], got.encodings[i])
					}
				}
				if protocol == protocolHTTP {
					assert.ElementsMatch(t, []string{"/v1/logs", "/v1/metrics"}, got.paths)
				}
				assertLog(t, got)
				assertMetric(t, got, 1)
			})
		}
	}
}

func attrMap(attrs []*commonpb.KeyValue) map[string]any {
	m := map[string]any{}
	for _, kv := range attrs {
		switch v := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			m[kv.Key] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			m[kv.Key] = v.IntValue
		case *commonpb.AnyValue_ArrayValue:
			values := make([]string, 0, len(v.ArrayValue.Values))
			for _, item := range v.ArrayValue.Values {
				values = append(values, item.GetStringValue())
			}
			m[kv.Key] = values
		default:
			m[kv.Key] = kv.Value.String()
		}
	}
	return m
}

func assertLog(t *testing.T, got *received) {
	t.Helper()
	rl := got.logs[0].ResourceLogs[0]
	assert.Equal(t, "falcosidekick", attrMap(rl.Resource.Attributes)["service.name"])
	scope := rl.ScopeLogs[0]
	assert.Equal(t, scopeName, scope.Scope.Name)
	rec := scope.LogRecords[0]
	assert.Equal(t, eventName, rec.EventName)
	assert.Equal(t, int32(otellog.SeverityError), int32(rec.SeverityNumber))
	assert.Equal(t, "Error", rec.SeverityText)
	assert.Equal(t, "File below a known binary directory opened for writing", rec.Body.GetStringValue())
	attrs := attrMap(rec.Attributes)
	assert.Equal(t, "Write below binary dir", attrs["falco.rule"])
	assert.Equal(t, "Error", attrs["falco.priority"])
	assert.Equal(t, "syscall", attrs["falco.source"])
	assert.Equal(t, "test-uuid-001", attrs["falco.uuid"])
	assert.Equal(t, "node-1", attrs["host.name"])
	assert.Equal(t, []string{"filesystem", "mitre_persistence"}, attrs["falco.tags"])
	assert.Equal(t, "touch /bin/hack", attrs["proc.cmdline"])
	assert.Equal(t, "/bin/hack", attrs["fd.name"])
	assert.NotContains(t, attrs, "falco.output")
}

func assertMetric(t *testing.T, got *received, want int64) {
	t.Helper()
	rm := got.metrics[len(got.metrics)-1].ResourceMetrics[0]
	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, counterName, m.Name)
	assert.Equal(t, counterUnit, m.Unit)
	sum := m.GetSum()
	require.NotNil(t, sum)
	assert.True(t, sum.IsMonotonic)
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, want, sum.DataPoints[0].GetAsInt())
	attrs := attrMap(sum.DataPoints[0].Attributes)
	assert.Equal(t, "Write below binary dir", attrs["falco.rule"])
	assert.Equal(t, "Error", attrs["falco.priority"])
	assert.NotContains(t, attrs, "falco.uuid")
}

// The SDK reads these variables unless every limit is set explicitly; output fields must arrive whole.
func TestOTELLimitVariablesHaveNoEffect(t *testing.T) {
	for _, key := range []string{"OTEL_LOGRECORD_ATTRIBUTE_VALUE_LENGTH_LIMIT", "OTEL_LOGRECORD_ATTRIBUTE_COUNT_LIMIT"} {
		t.Setenv(key, "2")
	}
	r, endpoint := startHTTPReceiver(t)
	d := newDriver(t, allSignals(endpoint, protocolHTTP, nil))
	evt := testutil.CreateValidEvent()
	require.NoError(t, d.Send(context.Background(), evt))
	attrs := attrMap(r.snapshot().logs[0].ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)
	assert.Equal(t, evt.Rule, attrs["falco.rule"])
	assert.Equal(t, "/bin/hack", attrs["fd.name"])
}

func TestSendBatchExportsOneRequestPerSignal(t *testing.T) {
	r, endpoint := startHTTPReceiver(t)
	d := newDriver(t, allSignals(endpoint, protocolHTTP, nil))
	first, second := testutil.CreateValidEvent(), testutil.CreateValidEvent()
	second.UUID = secondUUID
	require.NoError(t, d.SendBatch(context.Background(), []*event.Event{first, second}))
	got := r.snapshot()
	require.Len(t, got.logs, 1)
	assert.Len(t, got.logs[0].ResourceLogs[0].ScopeLogs[0].LogRecords, 2)
	assertMetric(t, got, 2)
}

func TestMetricRetryDoesNotCountTwice(t *testing.T) {
	r, endpoint := startHTTPReceiver(t)
	d := newDriver(t, map[string]any{"metrics": map[string]any{"endpoint": endpoint}})
	evt := testutil.CreateValidEvent()

	r.fail(1, http.StatusServiceUnavailable)
	require.Error(t, d.Send(context.Background(), evt))
	require.NoError(t, d.Send(context.Background(), evt), "retry of the same event")
	assertMetric(t, r.snapshot(), 1)

	next := testutil.CreateValidEvent()
	next.UUID = secondUUID
	require.NoError(t, d.Send(context.Background(), next))
	assertMetric(t, r.snapshot(), 2)
}

// The retry is for logs, which failed; metrics went through and must not count the event again.
func TestMetricRetryForAnotherSignalDoesNotCountTwice(t *testing.T) {
	r, endpoint := startHTTPReceiver(t)
	d := newDriver(t, allSignals(endpoint, protocolHTTP, nil))
	evt := testutil.CreateValidEvent()

	r.fail(1, http.StatusServiceUnavailable)
	require.Error(t, d.Send(context.Background(), evt))
	assertMetric(t, r.snapshot(), 1)
	require.NoError(t, d.Send(context.Background(), evt), "retry of the same event")
	assertMetric(t, r.snapshot(), 1)
}

// Concurrent batches: each event counted once and the last export carries the total.
func TestMetricConcurrentExportsCountEachEventOnce(t *testing.T) {
	r, endpoint := startHTTPReceiver(t)
	d := newDriver(t, map[string]any{"metrics": map[string]any{"endpoint": endpoint}})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			evt := testutil.CreateValidEvent()
			evt.UUID = fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
			assert.NoError(t, d.Send(context.Background(), evt))
			assert.NoError(t, d.Send(context.Background(), evt), "a retry after success")
		})
	}
	wg.Wait()
	assertMetric(t, r.snapshot(), 8)
}

func TestMetricExtraAttributes(t *testing.T) {
	s := &metricsSignal{extra: []string{"k8s.pod.name", "proc.pid", "missing"}}
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	evt.Tags = nil
	evt.OutputFields["k8s.pod.name"] = "web-0"
	evt.OutputFields["proc.pid"] = float64(42)
	got := map[attribute.Key]attribute.Value{}
	for _, kv := range s.attributes(evt) {
		got[kv.Key] = kv.Value
	}
	assert.Equal(t, "web-0", got["k8s.pod.name"].AsString())
	assert.Equal(t, int64(42), got["proc.pid"].AsInt64())
	assert.NotContains(t, got, attribute.Key("missing"))
	assert.NotContains(t, got, attribute.Key("host.name"), "empty hostname is omitted")
	assert.NotContains(t, got, attribute.Key("falco.tags"), "empty tags are omitted")
}

func TestExportErrorsKeepSecretsOut(t *testing.T) {
	for _, tc := range []struct {
		protocol, want string
	}{
		{protocol: protocolHTTP, want: "otlp send: logs: HTTP 401 Unauthorized; metrics: HTTP 401 Unauthorized"},
		{protocol: protocolGRPC, want: "otlp send: logs: Unauthenticated; metrics: Unauthenticated"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			var r *receiver
			var endpoint string
			if tc.protocol == protocolHTTP {
				r, endpoint = startHTTPReceiver(t)
				r.fail(2, http.StatusUnauthorized)
			} else {
				r, endpoint = startGRPCReceiver(t)
				r.fail(2, int(codes.Unauthenticated))
			}
			d := newDriver(t, allSignals(endpoint, tc.protocol, map[string]any{
				"headers": map[string]any{"Authorization": map[string]any{"secrets": []string{"Bearer " + secret}}},
			}))
			err := d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.True(t, output.IsPermanent(err))
			assert.NotContains(t, fmt.Sprintf("%v %+v", err, err), secret)
		})
	}
}

// TestExportFailureClassification follows https://opentelemetry.io/docs/specs/otlp/#failures.
func TestExportFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, want string
		fail                 int
		rejected             int64
		retryInfo            bool
		permanent            bool
	}{
		{name: "http throttled", protocol: protocolHTTP, fail: http.StatusTooManyRequests, want: "otlp logs: HTTP 429 Too Many Requests"},
		{name: "http bad gateway", protocol: protocolHTTP, fail: http.StatusBadGateway, want: "otlp logs: HTTP 502 Bad Gateway"},
		{name: "http unavailable", protocol: protocolHTTP, fail: http.StatusServiceUnavailable, want: "otlp logs: HTTP 503 Service Unavailable"},
		{name: "http gateway timeout", protocol: protocolHTTP, fail: http.StatusGatewayTimeout, want: "otlp logs: HTTP 504 Gateway Timeout"},
		{name: "http bad request", protocol: protocolHTTP, fail: http.StatusBadRequest, want: "otlp logs: HTTP 400 Bad Request", permanent: true},
		{name: "http request timeout", protocol: protocolHTTP, fail: http.StatusRequestTimeout, want: "otlp logs: HTTP 408 Request Timeout", permanent: true},
		{name: "http internal error", protocol: protocolHTTP, fail: http.StatusInternalServerError, want: "otlp logs: HTTP 500 Internal Server Error", permanent: true},
		{name: "http partial success", protocol: protocolHTTP, rejected: 1, want: "otlp logs: partial success", permanent: true},
		{name: "grpc unavailable", protocol: protocolGRPC, fail: int(codes.Unavailable), want: "otlp logs: Unavailable"},
		{name: "grpc resource exhausted", protocol: protocolGRPC, fail: int(codes.ResourceExhausted), want: "otlp logs: ResourceExhausted", permanent: true},
		{name: "grpc resource exhausted with retry info", protocol: protocolGRPC, fail: int(codes.ResourceExhausted), retryInfo: true,
			want: "otlp logs: ResourceExhausted"},
		{name: "grpc invalid argument", protocol: protocolGRPC, fail: int(codes.InvalidArgument), want: "otlp logs: InvalidArgument", permanent: true},
		{name: "grpc partial success", protocol: protocolGRPC, rejected: 1, want: "otlp logs: partial success", permanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *receiver
			var endpoint string
			if tc.protocol == protocolHTTP {
				r, endpoint = startHTTPReceiver(t)
			} else {
				r, endpoint = startGRPCReceiver(t)
			}
			r.fail(1, tc.fail)
			r.mu.Lock()
			r.retryInfo, r.rejectedLogs = tc.retryInfo, tc.rejected
			r.mu.Unlock()
			d := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": endpoint, "protocol": tc.protocol}})
			err := d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.Equal(t, tc.permanent, output.IsPermanent(err))
			assert.NotContains(t, fmt.Sprintf("%v %+v", err, err), secret)
		})
	}
}

func TestPartialSignalFailureIsRetriable(t *testing.T) {
	permanent := newDeliveryError(signalLogs, &exportResult{httpStatus: http.StatusBadRequest}, errors.New(secret))
	transient := newDeliveryError(signalMetrics, &exportResult{httpStatus: http.StatusServiceUnavailable}, errors.New(secret))
	err := joinFailures(context.Background(), []*shared.DeliveryError{permanent, transient})
	assert.Equal(t, "otlp send: logs: HTTP 400 Bad Request; metrics: HTTP 503 Service Unavailable", err.Error())
	assert.False(t, output.IsPermanent(err), "a retry can still deliver the transient signal")
	assert.True(t, output.IsPermanent(joinFailures(context.Background(), []*shared.DeliveryError{permanent, permanent})))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := joinFailures(ctx, []*shared.DeliveryError{permanent, transient})
	assert.ErrorIs(t, canceled, context.Canceled)
	assert.False(t, output.IsPermanent(canceled))
}

func TestHTTPRedirectPolicy(t *testing.T) {
	r, endpoint := startHTTPReceiver(t)
	redirect := httptest.NewServer(http.RedirectHandler(endpoint+"/v1/logs", http.StatusTemporaryRedirect))
	t.Cleanup(redirect.Close)
	d := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": redirect.URL}})
	err := d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Equal(t, "otlp logs: cross-origin redirect denied", err.Error(), "the shared policy refuses a redirect to another origin")
	assert.Empty(t, r.snapshot().logs)
}

// With the INSECURE variables set, an https endpoint used to get plain HTTP, its headers in clear.
func TestInsecureVariablesNeverDowngradeHTTPS(t *testing.T) {
	for _, key := range []string{"OTEL_EXPORTER_OTLP_INSECURE", "OTEL_EXPORTER_OTLP_LOGS_INSECURE", "OTEL_EXPORTER_OTLP_METRICS_INSECURE"} {
		t.Setenv(key, "true")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1")
	r := &receiver{}
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	signal := map[string]any{"endpoint": server.URL, "tls": map[string]any{"ca_file": caFile}}

	d := newDriver(t, map[string]any{"logs": signal, "metrics": signal})
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	got := r.snapshot()
	assert.Len(t, got.logs, 1)
	assert.Len(t, got.metrics, 1)
}

func TestHTTPSWithCAFile(t *testing.T) {
	r := &receiver{}
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))

	d := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": server.URL, "tls": map[string]any{"ca_file": caFile}}})
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Len(t, r.snapshot().logs, 1)

	untrusted := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": server.URL}})
	err := untrusted.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

func TestGRPCWithTLS(t *testing.T) {
	d := newDriver(t, map[string]any{"logs": map[string]any{
		"endpoint": "https://127.0.0.1:1", "protocol": "grpc", "tls": map[string]any{"server_name": "collector"},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	assert.Error(t, d.Send(ctx, testutil.CreateValidEvent()))
}

func TestInitFailsWhenHeaderFileDisappears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(secret), 0o600))
	drv, err := OutputType.New(map[string]any{"metrics": map[string]any{
		"endpoint": "http://c:4318", "headers": map[string]any{"X-Token": map[string]any{"files": []string{path}}},
	}}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	err = drv.Init(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp metrics")
	assert.NotContains(t, err.Error(), secret)
	assert.ErrorIs(t, drv.Send(context.Background(), testutil.CreateValidEvent()), core.ErrNotReady)
}

func TestInitFailsOnBadCAFile(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, []byte("not a certificate"), 0o600))
	drv, err := OutputType.New(map[string]any{
		"logs":    map[string]any{"endpoint": "http://c:4318"},
		"metrics": map[string]any{"endpoint": "https://c:4318", "tls": map[string]any{"ca_file": ca}},
	}, output.Deps{})
	require.NoError(t, err)
	err = drv.Init(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp metrics")
	assert.Empty(t, drv.(*driver).signals, "signals created before the failure are closed")
}

func TestNotReadyAndClose(t *testing.T) {
	drv, err := OutputType.New(map[string]any{"logs": map[string]any{"endpoint": "http://c:4318"}}, output.Deps{})
	require.NoError(t, err)
	assert.ErrorIs(t, drv.Send(context.Background(), testutil.CreateValidEvent()), core.ErrNotReady)
	assert.NoError(t, drv.Close())
	require.NoError(t, drv.Init(context.Background()))
	assert.NoError(t, drv.Close())
	assert.NoError(t, drv.Close())
}

func TestGlobalProvidersUntouched(t *testing.T) {
	tracer, meter, handler := otel.GetTracerProvider(), otel.GetMeterProvider(), otel.GetErrorHandler()
	_, endpoint := startHTTPReceiver(t)
	d := newDriver(t, allSignals(endpoint, protocolHTTP, nil))
	other := newDriver(t, allSignals(endpoint, protocolHTTP, nil))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	require.NoError(t, other.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, tracer, otel.GetTracerProvider())
	assert.Equal(t, meter, otel.GetMeterProvider())
	assert.Equal(t, handler, otel.GetErrorHandler())
}

func TestReturnsWhenContextEndsOnSilentDestination(t *testing.T) {
	endpoints := map[string]string{
		protocolHTTP: testutil.HangingHTTPServer(t).URL,
		protocolGRPC: "http://" + testutil.HangingTCPServer(t),
	}
	for protocol, endpoint := range endpoints {
		t.Run(protocol, func(t *testing.T) {
			d := newDriver(t, allSignals(endpoint, protocol, nil))
			calls := map[string]func(context.Context) error{
				"Send": func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) },
				"SendBatch": func(ctx context.Context) error {
					return d.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
				},
			}
			for name, call := range calls {
				_ = testutil.RequireReturnsOnCancel(t, name, call)
			}
			start := time.Now()
			_ = d.Close()
			assert.Less(t, time.Since(start), defaultTimeout*3+time.Second, "close is bounded")
		})
	}
}

func TestSeverityCoversEveryPriority(t *testing.T) {
	for _, p := range []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice, event.PriorityWarning,
		event.PriorityError, event.PriorityCritical, event.PriorityAlert, event.PriorityEmergency,
	} {
		assert.Contains(t, severities, p)
	}
	assert.Equal(t, otellog.SeverityFatal, severities[event.PriorityEmergency])
	assert.Equal(t, otellog.SeverityInfo2, severities[event.PriorityNotice])
}

func TestFieldAttribute(t *testing.T) {
	tests := []struct {
		value any
		want  attribute.Value
	}{
		{value: "x", want: attribute.StringValue("x")},
		{value: true, want: attribute.BoolValue(true)},
		{value: float64(3), want: attribute.Int64Value(3)},
		{value: 1.5, want: attribute.Float64Value(1.5)},
		{value: 7, want: attribute.IntValue(7)},
		{value: int64(8), want: attribute.Int64Value(8)},
		{value: json.Number("9"), want: attribute.Int64Value(9)},
		{value: json.Number("9.5"), want: attribute.StringValue("9.5")},
		{value: nil, want: attribute.StringValue("")},
		{value: []any{"a", 1}, want: attribute.StringValue("[a 1]")},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, fieldAttribute("k", tt.value).Value, "%v", tt.value)
	}
}

func TestOutputsCoexist(t *testing.T) {
	r1, e1 := startHTTPReceiver(t)
	r2, e2 := startGRPCReceiver(t)
	a := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": e1}})
	b := newDriver(t, map[string]any{"logs": map[string]any{"endpoint": e2, "protocol": "grpc"}})
	require.NoError(t, a.Send(context.Background(), testutil.CreateValidEvent()))
	require.NoError(t, b.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Len(t, r1.snapshot().logs, 1)
	assert.Len(t, r2.snapshot().logs, 1)
	assert.True(t, strings.HasPrefix(e2, "http://"))
}

type idleCounter struct {
	http.RoundTripper
	closed int
}

func (c *idleCounter) CloseIdleConnections() { c.closed++ }

func TestStatusRecorderReleasesIdleConnections(t *testing.T) {
	base := &idleCounter{RoundTripper: http.DefaultTransport}
	client := &http.Client{Transport: statusRecorder{base: base}}
	client.CloseIdleConnections()
	assert.Equal(t, 1, base.closed, "Close reaches the transport the recorder wraps")
}

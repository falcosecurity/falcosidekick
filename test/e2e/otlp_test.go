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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	envOTLPGRPC = "FALCOSIDEKICK_E2E_OTLP_GRPC"
	envOTLPHTTP = "FALCOSIDEKICK_E2E_OTLP_HTTP"
	// envOTLPFile is the output directory of the collector file exporter (testdata/otel-collector.yaml).
	envOTLPFile = "FALCOSIDEKICK_E2E_OTLP_FILE"
)

// OTLP JSON, as written by the collector file exporter.
type otlpAttribute struct {
	Value map[string]any `json:"value"`
	Key   string         `json:"key"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpResource struct {
	Attributes []otlpAttribute `json:"attributes"`
}

type otlpLogRecord struct {
	Body           map[string]any  `json:"body"`
	EventName      string          `json:"eventName"`
	SeverityText   string          `json:"severityText"`
	Attributes     []otlpAttribute `json:"attributes"`
	SeverityNumber int             `json:"severityNumber"`
}

type otlpDataPoint struct {
	AsInt      string          `json:"asInt"`
	Attributes []otlpAttribute `json:"attributes"`
}

type otlpMetric struct {
	Sum *struct {
		DataPoints  []otlpDataPoint `json:"dataPoints"`
		IsMonotonic bool            `json:"isMonotonic"`
	} `json:"sum"`
	Name string `json:"name"`
	Unit string `json:"unit"`
}

type otlpFileLine struct {
	ResourceLogs []struct {
		Resource  otlpResource `json:"resource"`
		ScopeLogs []struct {
			Scope      otlpScope       `json:"scope"`
			LogRecords []otlpLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
	ResourceMetrics []struct {
		Resource     otlpResource `json:"resource"`
		ScopeMetrics []struct {
			Scope   otlpScope    `json:"scope"`
			Metrics []otlpMetric `json:"metrics"`
		} `json:"scopeMetrics"`
	} `json:"resourceMetrics"`
}

func attrs(list []otlpAttribute) map[string]any {
	m := make(map[string]any, len(list))
	for _, a := range list {
		for _, v := range a.Value {
			m[a.Key] = v
		}
	}
	return m
}

func waitOTLPLine(t *testing.T, dir, file, marker string) otlpFileLine {
	t.Helper()
	path := filepath.Join(dir, file)
	var found []byte
	eventuallyf(t, func() bool {
		raw, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for scanner.Scan() {
			if bytes.Contains(scanner.Bytes(), []byte(marker)) {
				found = append([]byte(nil), scanner.Bytes()...)
			}
		}
		return found != nil
	}, "marker %s in %s", marker, path)
	var line otlpFileLine
	require.NoError(t, json.Unmarshal(found, &line))
	return line
}

func otlpOutput(endpoint, protocol, token string) string {
	out := "otlp:\n"
	for _, signal := range []string{"logs", "metrics"} {
		out += fmt.Sprintf("  %s:\n    endpoint: %q\n    protocol: %s\n    timeout: 2s\n", signal, endpoint, protocol)
		out += fmt.Sprintf("    headers:\n      Authorization:\n        secrets: [%q]\n", "Bearer "+token)
		if signal == "metrics" {
			out += "    extra_attributes: [e2e.marker]\n"
		}
	}
	return out
}

func TestOTLPDeliversSignals(t *testing.T) {
	dir := requireEnv(t, envOTLPFile)
	endpoints := map[string]string{
		"grpc":          requireEnv(t, envOTLPGRPC),
		"http/protobuf": requireEnv(t, envOTLPHTTP),
	}
	for protocol, endpoint := range endpoints {
		t.Run(protocol, func(t *testing.T) {
			token := "token-" + newMarker(t)
			sk := startSidekick(t, otlpOutput(endpoint, protocol, token))
			marker := newMarker(t)
			sk.postEvent(t, marker)

			logs := waitOTLPLine(t, dir, "logs.json", marker)
			require.NotEmpty(t, logs.ResourceLogs)
			rl := logs.ResourceLogs[len(logs.ResourceLogs)-1]
			assert.Equal(t, "falcosidekick", attrs(rl.Resource.Attributes)["service.name"])
			assert.Equal(t, "github.com/falcosecurity/falcosidekick", rl.ScopeLogs[0].Scope.Name)
			record := rl.ScopeLogs[0].LogRecords[0]
			assert.Equal(t, "falco.alert", record.EventName)
			assert.Equal(t, 13, record.SeverityNumber, "WARN")
			assert.Equal(t, "Warning", record.SeverityText)
			assert.Equal(t, "e2e event "+marker, record.Body["stringValue"])
			recordAttrs := attrs(record.Attributes)
			assert.Equal(t, "E2E "+marker, recordAttrs["falco.rule"])
			assert.Equal(t, "Warning", recordAttrs["falco.priority"])
			assert.Equal(t, "e2e-host", recordAttrs["host.name"])
			assert.Equal(t, marker, recordAttrs["e2e.marker"])

			metrics := waitOTLPLine(t, dir, "metrics.json", marker)
			var point *otlpDataPoint
			for _, rm := range metrics.ResourceMetrics {
				for _, sm := range rm.ScopeMetrics {
					for _, m := range sm.Metrics {
						if m.Name != "falcosecurity.falco.rules.matches" || m.Sum == nil {
							continue
						}
						assert.Equal(t, "{match}", m.Unit)
						assert.True(t, m.Sum.IsMonotonic)
						for i := range m.Sum.DataPoints {
							if attrs(m.Sum.DataPoints[i].Attributes)["e2e.marker"] == marker {
								point = &m.Sum.DataPoints[i]
							}
						}
					}
				}
			}
			require.NotNil(t, point, "data point for %s", marker)
			assert.Equal(t, "1", point.AsInt)
			assert.Equal(t, "E2E "+marker, attrs(point.Attributes)["falco.rule"])
			assert.Equal(t, "Warning", attrs(point.Attributes)["falco.priority"])

			st := sk.waitStatus(t, "otlp", func(st outputStatus) bool { return st.SentTotal == 1 })
			assert.Zero(t, st.FailedTotal)
			assert.NotContains(t, sk.logs.String(), token)
			assert.NotContains(t, outputConfig(t, sk, "otlp"), token)
		})
	}
}

func TestOTLPReportsUnreachableCollector(t *testing.T) {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	token := "token-" + newMarker(t)
	sk := startSidekick(t, otlpOutput(endpoint, "grpc", token))
	st := sk.status(t, "otlp")
	assert.Empty(t, st.LastWarning, "OTLP has no probe")

	sk.postEvent(t, newMarker(t))
	st = sk.waitStatus(t, "otlp", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	t.Logf("last_error: %s", st.LastError)
	assert.Equal(t, "otlp send: logs: Unavailable; metrics: Unavailable", st.LastError)
	assert.NotContains(t, sk.logs.String(), token)
}

// The traces signal was removed: a configuration that still has it does not start.
func TestOTLPRefusesTraces(t *testing.T) {
	logs := startSidekickFails(t, "otlp:\n  traces:\n    endpoint: http://127.0.0.1:4318\n")
	assert.Contains(t, logs, "unknown keys: traces")
}

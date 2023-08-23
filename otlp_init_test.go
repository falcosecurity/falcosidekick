package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type mockOS struct {
	envMap map[string]string
}

func newMockOS() *mockOS {
	return &mockOS{
		envMap: make(map[string]string),
	}
}

func (m *mockOS) Getenv(key string) string {
	if v, ok := m.envMap[key]; ok {
		return v
	}
	return ""
}

func (m *mockOS) Setenv(key, value string) error {
	m.envMap[key] = value
	return nil
}

func TestOtlpInit(t *testing.T) {
	cases := []struct {
		msg         string
		key         string
		value       string
		wantedKey   string
		wantedValue string
	}{
		{
			msg:         "Verify OTEL_EXPORTER_OTLP_ENDPOINT (sdk) sets ${OTLP_TRACES_ENDPOINT}/v1/traces (internal)",
			key:         "OTEL_EXPORTER_OTLP_ENDPOINT",
			value:       "http://localhost:4318",
			wantedKey:   "OTLP_TRACES_ENDPOINT",
			wantedValue: "http://localhost:4318/v1/traces",
		},
		{
			msg:         "Verify OTEL_EXPORTER_OTLP_TRACES (sdk) sets ${OTLP_TRACES_ENDPOINT} (internal)",
			key:         "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
			value:       "http://localhost:4318/v1/traces",
			wantedKey:   "OTLP_TRACES_ENDPOINT",
			wantedValue: "http://localhost:4318/v1/traces",
		},
		{
			msg:         "Verify OTLP_TRACES_ENDPOINT (internal) sets ${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT} (sdk)",
			key:         "OTLP_TRACES_ENDPOINT",
			value:       "http://localhost:4318/v1/traces",
			wantedKey:   "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
			wantedValue: "http://localhost:4318/v1/traces",
		},
		{
			msg:         "Verify OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (sdk) is not set by default",
			key:         "FOO",
			value:       "bar",
			wantedKey:   "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
			wantedValue: "",
		},
	}
	for _, c := range cases {
		otlpOS = newMockOS()
		otlpOS.Setenv(c.key, c.value)
		otlpSetEnvs()
		require.Equal(t, c.wantedValue, otlpOS.Getenv(c.wantedKey), c.msg)
	}
}

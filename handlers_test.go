// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The SMTP, Kafka, Grafana and GCP Cloud Run clients are only created when
// more settings than the one checked by forwardEvent are set. With a partial
// configuration, forwardEvent must not dispatch to these nil clients.
func TestForwardEventSkipsOutputsWithoutClient(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	prevConfig := config
	t.Cleanup(func() { config = prevConfig })

	config = &types.Configuration{}
	config.SMTP.HostPort = "localhost:25"
	config.Kafka.HostPort = "localhost:9092"
	config.Grafana.HostPort = "http://localhost:3000"
	config.GCP.CloudRun.Endpoint = "http://localhost:8080"

	forwardEvent(types.FalcoPayload{Rule: "rule", Priority: types.Critical, Time: time.Now()})

	time.Sleep(500 * time.Millisecond)
	require.NotContains(t, buf.String(), "recovered from panic")
}

func TestKubernetesFieldsIgnoresNonStringValues(t *testing.T) {
	// output_fields is decoded from the request body, so a field can hold any
	// JSON value. A bare j.(string) panicked on all of these.
	tests := map[string]map[string]interface{}{
		"namespace as a number":  {"k8s.ns.name": 42},
		"pod as a number":        {"k8s.pod.name": 42},
		"namespace as an object": {"k8s.ns.name": map[string]interface{}{"a": 1}},
		"pod as a list":          {"k8s.pod.name": []interface{}{"a"}},
		"namespace as a bool":    {"k8s.ns.name": true},
		"nil value":              {"k8s.ns.name": nil},
	}

	for name, outputFields := range tests {
		t.Run(name, func(t *testing.T) {
			namespace, pod := kubernetesFields(outputFields)

			if namespace != "" || pod != "" {
				t.Fatalf("expected both empty, got namespace=%q pod=%q", namespace, pod)
			}
		})
	}
}

func TestKubernetesFieldsKeepsStringValues(t *testing.T) {
	namespace, pod := kubernetesFields(map[string]interface{}{
		"k8s.ns.name":  "kube-system",
		"k8s.pod.name": "falco-abcde",
		"proc.name":    "falco",
	})

	if namespace != "kube-system" {
		t.Fatalf("namespace: got %q", namespace)
	}
	if pod != "falco-abcde" {
		t.Fatalf("pod: got %q", pod)
	}
}

func TestKubernetesFieldsKeepsAStringWhenTheOtherIsNot(t *testing.T) {
	namespace, pod := kubernetesFields(map[string]interface{}{
		"k8s.ns.name":  "kube-system",
		"k8s.pod.name": 42,
	})

	if namespace != "kube-system" {
		t.Fatalf("namespace: got %q", namespace)
	}
	if pod != "" {
		t.Fatalf("pod: got %q", pod)
	}
}

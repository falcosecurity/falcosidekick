// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewDynatracePayload(t *testing.T) {
	expectedOutput := dtPayload{
		Payload: []dtLogMessage{
			{
				Timestamp:     "2001-01-01T01:10:00Z",
				EventName:     "Test rule",
				EventProvider: "Falco",
				Severity:      "Debug",
				HostName:      "test-host",
				LogSource:     "syscalls",
				Content: dtLogContent{
					Output: "This is a test from falcosidekick",
					OutputFields: map[string]interface{}{
						"proc.name": "falcosidekick",
						"proc.tty":  float64(1234),
					},
					Tags: []string{"test", "example"},
				},
				ProcessExecutableName: "falcosidekick",
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	output := newDynatracePayload(f)
	require.Equal(t, output, expectedOutput)
}

func TestNewDynatracePayloadWithExtraOutputFields(t *testing.T) {
	const ContainerId = "77d156711504"
	const ContainerName = "hello-world"
	const ContainerImageName = "falcosecurity/falco:latest"
	const K8sNamespaceName = "falco"
	const K8sPodName = "falco-khx2g"
	const ProcessExecutableName = "falcosidekick"
	const SpanId = 1337
	const MitreTechnique = "T1059"
	const MitreTactic = "mitre_execution"

	expectedOutput := dtPayload{
		Payload: []dtLogMessage{
			{
				Timestamp:     "2001-01-01T01:10:00Z",
				EventName:     "Test rule",
				EventProvider: "Falco",
				Severity:      "Debug",
				HostName:      "test-host",
				LogSource:     "syscalls",
				Content: dtLogContent{
					Output: "This is a test from falcosidekick",
					OutputFields: map[string]interface{}{
						"container.id":    ContainerId,
						"container.name":  ContainerName,
						"container.image": ContainerImageName,
						"k8s.ns.name":     K8sNamespaceName,
						"k8s.pod.name":    K8sPodName,
						"k8s.pod.id":      nil,
						"proc.name":       ProcessExecutableName,
						"span.id":         SpanId,
					},
					Tags: []string{"test", "example", MitreTechnique, MitreTactic},
				},
				ContainerId:           ContainerId,
				ContainerName:         ContainerName,
				ContainerImageName:    ContainerImageName,
				K8sNamespaceName:      K8sNamespaceName,
				K8sPodName:            K8sPodName,
				ProcessExecutableName: ProcessExecutableName,
				SpanId:                fmt.Sprintf("%v", SpanId),
				MitreTactic:           MitreTactic,
				MitreTechnique:        MitreTechnique,
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	delete(f.OutputFields, "proc.tty")
	f.OutputFields["container.id"] = ContainerId
	f.OutputFields["container.name"] = ContainerName
	f.OutputFields["container.image"] = ContainerImageName
	f.OutputFields["k8s.ns.name"] = K8sNamespaceName
	f.OutputFields["k8s.pod.name"] = K8sPodName
	f.OutputFields["k8s.pod.id"] = nil
	f.OutputFields["proc.name"] = ProcessExecutableName
	f.OutputFields["span.id"] = SpanId
	f.Tags = append(f.Tags, "T1059")
	f.Tags = append(f.Tags, "mitre_execution")

	output := newDynatracePayload(f)
	require.Equal(t, output, expectedOutput)
}

func TestNewDynatracePayloadWithNonStringOutputFields(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	// output_fields values are not guaranteed to be strings. Feed wrong types
	// into the fields that map to semantic attributes and make sure building
	// the payload does not panic.
	f.OutputFields["container.id"] = 12345
	f.OutputFields["container.name"] = true
	f.OutputFields["k8s.ns.name"] = float64(42)
	f.OutputFields["proc.name"] = []string{"unexpected"}
	f.OutputFields["span.id"] = false

	var output dtPayload
	require.NotPanics(t, func() {
		output = newDynatracePayload(f)
	})

	msg := output.Payload[0]
	// non-string values are ignored rather than crashing the process
	require.Empty(t, msg.ContainerId)
	require.Empty(t, msg.ContainerName)
	require.Empty(t, msg.K8sNamespaceName)
	require.Empty(t, msg.ProcessExecutableName)
	// span.id is rendered with a type-agnostic format
	require.Equal(t, "false", msg.SpanId)
}

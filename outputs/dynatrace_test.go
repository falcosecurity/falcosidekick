// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"

	"github.com/stretchr/testify/require"
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
				SpanId:                strconv.Itoa(SpanId),
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

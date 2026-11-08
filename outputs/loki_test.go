// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewLokiPayload(t *testing.T) {
	expectedOutput := lokiPayload{
		Streams: []lokiStream{
			{
				Stream: map[string]string{
					"hostname": "test-host",
					"tags":     "example,test",
					"rule":     "Test rule",
					"source":   "syscalls",
					"priority": "Debug",
				},
				Values: []lokiValue{[]string{"978311400000000000", "This is a test from falcosidekick"}},
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	output := newLokiPayload(f, &types.Configuration{})

	require.Equal(t, output, expectedOutput)
}

func TestNewLokiPayloadSanitizesLabelNames(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	f.OutputFields = map[string]interface{}{
		"k8s.pod.label[app.kubernetes.io/name]": "nginx",
		"k8s.pod.label[pod-template-hash]":      "abc",
		"proc.aname[2]":                         "bash",
		"1st.field":                             "x",
	}
	config := &types.Configuration{}
	config.Loki.ExtraLabelsList = []string{
		"k8s.pod.label[app.kubernetes.io/name]",
		"k8s.pod.label[pod-template-hash]",
		"proc.aname[2]",
		"1st.field",
	}

	stream := newLokiPayload(f, config).Streams[0].Stream

	require.Equal(t, "nginx", stream["k8s_pod_labelapp_kubernetes_io_name"])
	require.Equal(t, "abc", stream["k8s_pod_labelpod_template_hash"])
	require.Equal(t, "bash", stream["proc_aname2"])
	require.Equal(t, "x", stream["_1st_field"])
	valid := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	for name := range stream {
		require.Truef(t, valid.MatchString(name), "invalid Loki label name %q", name)
	}
}

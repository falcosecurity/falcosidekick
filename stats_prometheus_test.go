// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestFalcoNewCounterVec(t *testing.T) {
	c := &types.Configuration{
		Customfields: make(map[string]string),
	}
	c.Customfields["test"] = "foo"
	c.Customfields["should*fail"] = "bar"

	cv := getFalcoNewCounterVec(c)
	shouldbe := []string{"hostname", "rule", "priority", "priority_raw", "source", "k8s_ns_name", "k8s_pod_name", "test"}
	mm, err := cv.GetMetricWithLabelValues(shouldbe...)
	if err != nil {
		t.Errorf("Error getting Metrics from promauto")
	}
	metricDescString := mm.Desc().String()
	require.Equal(t, metricDescString, "Desc{fqName: \"falcosecurity_falcosidekick_falco_events_total\", help: \"\", constLabels: {}, variableLabels: {hostname,rule,priority,priority_raw,source,k8s_ns_name,k8s_pod_name,test}}")
}

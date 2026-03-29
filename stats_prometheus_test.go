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
	c.Customfields["k8s.cluster.name"] = "my-cluster"

	cv := getFalcoNewCounterVec(c)
	shouldbe := []string{"hostname", "rule", "priority", "priority_raw", "source", "k8s_ns_name", "k8s_pod_name", "k8s_cluster_name", "test"}
	mm, err := cv.GetMetricWithLabelValues(shouldbe...)
	if err != nil {
		t.Errorf("Error getting Metrics from promauto")
	}
	metricDescString := mm.Desc().String()
	require.Contains(t, metricDescString, "k8s_cluster_name")
	require.Contains(t, metricDescString, "test")
	require.NotContains(t, metricDescString, "should*fail")
	require.NotContains(t, metricDescString, "k8s.cluster.name")
}

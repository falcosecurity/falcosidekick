// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	shouldbe := []string{"hostname", "rule", "priority", "source", "k8s_ns_name", "k8s_pod_name", "test"}
	mm, err := cv.GetMetricWithLabelValues(shouldbe...)
	if err != nil {
		t.Errorf("Error getting Metrics from promauto")
	}
	metricDescString := mm.Desc().String()
	require.Equal(t, metricDescString, "Desc{fqName: \"falco_events\", help: \"\", constLabels: {}, variableLabels: {hostname,rule,priority,source,k8s_ns_name,k8s_pod_name,test}}")
}

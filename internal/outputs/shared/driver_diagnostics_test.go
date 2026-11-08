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

package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/alertmanager"
	"github.com/falcosecurity/falcosidekick/internal/outputs/elasticsearch"
	"github.com/falcosecurity/falcosidekick/internal/outputs/loki"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

func TestHTTPDriversNeverEchoConfiguredURLs(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	urls := map[string]string{
		"malformed":          "https://u:" + sentinel + "@ho st/x",
		"unsupported scheme": "ftp://u:" + sentinel + "@host/x",
		"missing scheme":     "host/" + sentinel,
	}
	drivers := []struct {
		config func(value string) map[string]any
		name   string
		kind   output.Type
	}{
		{name: "webhook", kind: webhook.OutputType, config: func(v string) map[string]any { return map[string]any{"host": v} }},
		{name: "slack", kind: slack.OutputType, config: func(v string) map[string]any { return map[string]any{"host": v, "secret_endpoint": "/services/x"} }},
		{name: "loki", kind: loki.OutputType, config: func(v string) map[string]any { return map[string]any{"host": v} }},
		{name: "elasticsearch", kind: elasticsearch.OutputType, config: func(v string) map[string]any {
			return map[string]any{"host": v, "index": "falco"}
		}},
		{name: "alertmanager", kind: alertmanager.OutputType, config: func(v string) map[string]any {
			return map[string]any{"hosts": []string{v}}
		}},
	}
	for _, driver := range drivers {
		for name, value := range urls {
			t.Run(driver.name+"/"+name, func(t *testing.T) {
				_, err := driver.kind.New(driver.config(value), output.Deps{})
				require.Error(t, err)
				assert.Contains(t, err.Error(), driver.name)
				assert.NotContains(t, err.Error(), sentinel)
			})
		}
	}
}

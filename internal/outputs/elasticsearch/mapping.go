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

package elasticsearch

import (
	"context"
	"fmt"
	"net/http"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// createIndexTemplate creates a composable index template using the
// _index_template API (ES 7.8+, composable templates).
// since ES 7.8 and will be removed in ES 9.x.
func (d *driver) createIndexTemplate(ctx context.Context) error {
	templateURL, err := d.cfg.URL(d.cfg.Host, "/_index_template/"+d.cfg.Index, nil)
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "target", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, templateURL, http.NoBody)
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "build request", err)
	}
	if checkErr := d.sender.Do(ctx, req); checkErr == nil {
		d.logger.Info("index template already exists", "index", d.cfg.Index)
		return nil
	}

	shards := d.cfg.NumberOfShards
	if shards <= 0 {
		shards = 3
	}
	replicas := d.cfg.NumberOfReplicas
	if replicas < 0 {
		replicas = 3
	}

	pattern := d.cfg.Index + "-*"
	if d.cfg.Suffix == suffixNone {
		pattern = d.cfg.Index
	}

	tmpl := map[string]any{
		"index_patterns": []string{pattern},
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   shards,
				"number_of_replicas": replicas,
			},
			"mappings": buildMappings(),
		},
	}

	if err := d.sender.SendJSON(ctx, http.MethodPut, templateURL, tmpl); err != nil {
		return fmt.Errorf("elasticsearch index template create: %w", err)
	}

	d.logger.Info("index template created", "index", d.cfg.Index)
	return nil
}

// buildMappings returns Elasticsearch mappings for Falco events.
// Explicit types for known stable fields prevent mapping explosions.
// Dynamic template for output_fields handles variable Falco fields.
func buildMappings() map[string]any {
	return map[string]any{
		"dynamic_templates": []map[string]any{
			{
				"output_fields_as_keyword": map[string]any{
					"path_match": "output_fields.*",
					"mapping":    textWithKeyword(256),
				},
			},
		},
		"properties": map[string]any{
			"@timestamp": map[string]any{"type": "date"},
			"uuid":       map[string]any{"type": "keyword"},
			"rule":       textWithKeyword(256),
			"output":     textWithKeyword(2048),
			"priority":   map[string]any{"type": "keyword"},
			"source":     map[string]any{"type": "keyword"},
			"hostname":   textWithKeyword(256),
			"tags":       map[string]any{"type": "keyword"},
		},
	}
}

// textWithKeyword returns an ES mapping for a text field with a keyword
// sub-field. This is the standard dual-purpose mapping: full-text searchable
// via the text field, exact-match and aggregatable via the keyword sub-field.
func textWithKeyword(ignoreAbove int) map[string]any {
	return map[string]any{
		"type": "text",
		"fields": map[string]any{
			"keyword": map[string]any{
				"type":         "keyword",
				"ignore_above": ignoreAbove,
			},
		},
	}
}

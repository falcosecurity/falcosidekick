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
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// bulkFilterPath minimizes the ES bulk response payload by requesting only
// the fields needed for error handling.
const bulkFilterPath = "items.*.status,items.*.error.type,items.*.error.reason"

// bulkResponse represents the Elasticsearch _bulk API response.
type bulkResponse struct {
	Items  []bulkItemAction `json:"items"`
	Errors bool             `json:"errors"`
}

// bulkItemAction wraps a single bulk response item.
// Uses "create" because we send append-only events (not "index").
type bulkItemAction struct {
	Create bulkItemResult `json:"create"`
}

// bulkItemResult holds the status and error for a single bulk item.
type bulkItemResult struct {
	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
	Status int `json:"status"`
}

// buildBulkBody encodes events as NDJSON for the _bulk API.
// Uses "create" action (append-only, required for data streams).
func (d *driver) buildBulkBody(events []*event.Event) ([]byte, error) {
	var body []byte
	index := d.resolveIndex()

	for _, evt := range events {
		action := fmt.Sprintf(`{"create":{"_index":%q}}`, index)
		data, err := d.marshalEvent(evt)
		if err != nil {
			return nil, shared.WrapDeliveryError("elasticsearch", "marshal", err)
		}
		body = append(body, action...)
		body = append(body, '\n')
		body = append(body, data...)
		body = append(body, '\n')
	}

	return body, nil
}

// parseBulkResponse inspects the per-item results from a bulk response.
// Fast-path: skips JSON parsing when no errors are present.
// Item-level inspection: success is status <= 201 with no error.type.
func (d *driver) parseBulkResponse(body []byte, expectedItems int) error {
	if len(body) == 0 {
		return nil
	}

	// Fast path: no errors in response, skip JSON parsing entirely.
	if !bytes.Contains(body, []byte(`"errors":true`)) {
		return nil
	}

	var resp bulkResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return shared.WrapDeliveryError("elasticsearch", "response", err)
	}

	var failed int
	for _, item := range resp.Items {
		r := item.Create
		if r.Status > 201 || r.Error.Type != "" {
			failed++
			d.logger.Warn("bulk item failed",
				"status", r.Status,
				"error_type", classifyBulkError(r.Error.Type),
			)
		}
	}

	if failed == 0 {
		return nil
	}

	succeeded := expectedItems - failed
	d.logger.Error("bulk request partial failure",
		"total", expectedItems,
		"failed", failed,
		"succeeded", succeeded,
	)

	return fmt.Errorf("elasticsearch: bulk indexed %d/%d, %d failed", succeeded, expectedItems, failed)
}

func classifyBulkError(code string) string {
	switch code {
	case "document_parsing_exception", "mapper_parsing_exception", "es_rejected_execution_exception",
		"version_conflict_engine_exception", "index_not_found_exception":
		return code
	default:
		return "unknown error"
	}
}

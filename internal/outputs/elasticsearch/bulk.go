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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// bulkFilterPath keeps only the fields needed to account for every item.
const bulkFilterPath = "errors,items.*.status,items.*.error.type"

// conflictError is the bulk error type for a document that already exists.
const conflictError = "version_conflict_engine_exception"

type bulkResponse struct {
	Errors *bool            `json:"errors"`
	Items  []bulkItemAction `json:"items"`
}

type bulkItemAction struct {
	Create *bulkItemResult `json:"create"`
}

// bulkItemResult omits the error reason because it can echo document content.
type bulkItemResult struct {
	Error struct {
		Type string `json:"type"`
	} `json:"error"`
	Status int `json:"status"`
}

// buildBulkBody uses create, required by data streams, and the event UUID as _id so a retry cannot index twice.
func (d *driver) buildBulkBody(events []*event.Event) ([]byte, error) {
	var body []byte
	index := d.resolveIndex()

	for _, evt := range events {
		action, err := bulkAction(index, evt.UUID)
		if err != nil {
			return nil, shared.WrapDeliveryError("elasticsearch", "marshal", err)
		}
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

func bulkAction(index, id string) ([]byte, error) {
	type meta struct {
		Index string `json:"_index"`
		ID    string `json:"_id,omitempty"`
	}
	return json.Marshal(map[string]meta{"create": {Index: index, ID: id}})
}

// parseBulkResponse counts an item that already exists from an earlier attempt as delivered.
func (d *driver) parseBulkResponse(body []byte, expectedItems int) error {
	var resp bulkResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return shared.WrapDeliveryError("elasticsearch", "response", err)
	}
	if resp.Errors == nil || len(resp.Items) != expectedItems {
		d.logger.Error("bulk response incomplete", "expected", expectedItems, "items", len(resp.Items))
		return shared.NewProtocolError("elasticsearch", "incomplete bulk response")
	}

	var failed, existing int
	for _, item := range resp.Items {
		r := item.Create
		switch {
		case r == nil:
			failed++
			d.logger.Warn("bulk item failed", "status", 0, "error_type", "unknown error")
		case r.Status == http.StatusConflict && r.Error.Type == conflictError:
			existing++
		case r.Status >= 200 && r.Status < 300 && r.Error.Type == "":
		default:
			failed++
			d.logger.Warn("bulk item failed",
				"status", r.Status,
				"error_type", classifyBulkError(r.Error.Type),
			)
		}
	}
	if existing > 0 {
		d.logger.Debug("bulk items already indexed", "count", existing)
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

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

package otlp

import (
	"encoding/json"
	"fmt"
	"math"

	"go.opentelemetry.io/otel/attribute"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

// Attribute keys of the event itself; output fields keep their Falco names.
const (
	attrRule     = "falco.rule"
	attrPriority = "falco.priority"
	attrSource   = "falco.source"
	attrUUID     = "falco.uuid"
	attrTags     = "falco.tags"
	attrOutput   = "falco.output"
	attrHostname = string(semconv.HostNameKey)

	// scopeName is the instrumentation scope of every signal.
	scopeName = "github.com/falcosecurity/falcosidekick"
)

// reservedAttributes cannot be taken by metrics.extra_attributes.
var reservedAttributes = []string{attrRule, attrPriority, attrSource, attrUUID, attrTags, attrOutput, attrHostname}

func newResource() *sdkresource.Resource {
	return sdkresource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName("falcosidekick"),
		semconv.ServiceVersion(version.Version),
	)
}

func eventAttributes(evt *event.Event) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 6+len(evt.OutputFields))
	attrs = append(attrs,
		attribute.String(attrRule, evt.Rule),
		attribute.String(attrPriority, evt.Priority.String()),
		attribute.String(attrSource, evt.Source),
		attribute.String(attrUUID, evt.UUID),
	)
	attrs = appendIdentity(attrs, evt)
	for _, key := range shared.SortMapKeys(evt.OutputFields) {
		attrs = append(attrs, fieldAttribute(key, evt.OutputFields[key]))
	}
	return attrs
}

func appendIdentity(attrs []attribute.KeyValue, evt *event.Event) []attribute.KeyValue {
	if evt.Hostname != "" {
		attrs = append(attrs, attribute.String(attrHostname, evt.Hostname))
	}
	if len(evt.Tags) > 0 {
		attrs = append(attrs, attribute.StringSlice(attrTags, evt.Tags))
	}
	return attrs
}

// fieldAttribute keeps the JSON type of an output field value.
func fieldAttribute(key string, value any) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case bool:
		return attribute.Bool(key, v)
	case float64:
		if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
			return attribute.Int64(key, int64(v))
		}
		return attribute.Float64(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return attribute.Int64(key, n)
		}
		return attribute.String(key, v.String())
	case nil:
		return attribute.String(key, "")
	default:
		return attribute.String(key, fmt.Sprint(v))
	}
}

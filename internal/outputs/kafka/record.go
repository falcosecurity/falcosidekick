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

package kafka

import (
	"encoding/json"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// buildRecord creates a Kafka record from a Falco event with key, headers, and topic resolution.
func (d *driver) buildRecord(evt *event.Event) (*kgo.Record, error) {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil, fmt.Errorf("kafka marshal: %w", err)
	}

	return &kgo.Record{
		Topic:   d.resolveTopic(evt),
		Value:   data,
		Key:     d.resolveKey(evt),
		Headers: buildHeaders(evt),
	}, nil
}

// resolveTopic returns the topic for this event.
// If topic_field is configured and the field exists in the event, use it.
// Otherwise use the default static topic.
func (d *driver) resolveTopic(evt *event.Event) string {
	if d.cfg.TopicField != "" {
		if v, ok := evt.OutputFields[d.cfg.TopicField]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return d.cfg.Topic
}

// resolveKey returns the message key for partition affinity.
// Priority: message_key_field (dynamic) > message_key (static) > nil (round-robin).
func (d *driver) resolveKey(evt *event.Event) []byte {
	if d.cfg.MessageKeyField != "" {
		if v, ok := evt.OutputFields[d.cfg.MessageKeyField]; ok {
			if s, ok := v.(string); ok && s != "" {
				return []byte(s)
			}
		}
	}
	if d.cfg.MessageKey != "" {
		return []byte(d.cfg.MessageKey)
	}
	return nil
}

// buildHeaders creates Kafka record headers for consumer-side routing/filtering.
func buildHeaders(evt *event.Event) []kgo.RecordHeader {
	return []kgo.RecordHeader{
		{Key: "content-type", Value: []byte("application/json")},
		{Key: "falco.rule", Value: []byte(evt.Rule)},
		{Key: "falco.priority", Value: []byte(string(evt.Priority))},
		{Key: "falco.source", Value: []byte(evt.Source)},
	}
}

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

package cloudevents

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// HTTP protocol binding, binary content mode:
// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md#31-binary-content-mode
const (
	specVersion = "1.0"
	eventType   = "falco.rule.output.v1"
	contentType = "application/json"
	headerAttr  = "Ce-"
)

// attributes returns the context attributes of evt. Built-in extensions
// come first so configured extensions replace them, as in v2.
func attributes(evt *event.Event, source string, extensions map[string]string) map[string]string {
	id := evt.UUID
	if id == "" {
		id = uuid.NewString()
	}
	attrs := map[string]string{
		"specversion": specVersion,
		"id":          id,
		"source":      source,
		"type":        eventType,
		"time":        evt.Time.UTC().Format(time.RFC3339Nano),
		"priority":    evt.Priority.String(),
		"rule":        ceString(evt.Rule),
		"eventsource": ceString(evt.Source),
	}
	if evt.Hostname != "" {
		attrs["hostname"] = ceString(evt.Hostname)
	}
	for key, value := range extensions {
		attrs[key] = value
	}
	return attrs
}

// ceString makes an event-derived value a valid CloudEvents String, which
// excludes control characters, surrogates and noncharacters: each one, and
// each invalid UTF-8 sequence, becomes a space.
// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md#type-system
func ceString(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r),
			r >= 0xFDD0 && r <= 0xFDEF, r&0xFFFE == 0xFFFE:
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, " "))
}

// newRequest builds the binary-mode request: each attribute is a ce- header
// and the body is the Falco event as JSON.
func newRequest(ctx context.Context, target string, evt *event.Event, source string, extensions map[string]string) (*http.Request, error) {
	body, err := json.Marshal(evt)
	if err != nil {
		return nil, shared.WrapDeliveryError(name, "marshal", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, shared.WrapDeliveryError(name, "request", err)
	}
	req.Header.Set("Content-Type", contentType)
	for key, value := range attributes(evt, source, extensions) {
		req.Header.Set(headerAttr+key, encodeHeaderValue(value))
	}
	return req, nil
}

// encodeHeaderValue percent-encodes space, double quote, percent and every
// byte outside printable ASCII, as the binding requires for header values.
func encodeHeaderValue(s string) string {
	const hex = "0123456789ABCDEF"
	b := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c < 0x21 || c > 0x7E || c == '"' || c == '%' {
			b = append(b, '%', hex[c>>4], hex[c&0x0F])
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

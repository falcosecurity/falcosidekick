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

//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	teamsSignature = "e2eTeamsSignature"
	teamsPath      = "/workflows/e2e0workflow/triggers/manual/paths/invoke"
)

// teamsMessage mirrors the Workflows Teams webhook trigger body for Adaptive Cards:
// https://learn.microsoft.com/en-us/connectors/teams/
type teamsMessage struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string          `json:"contentType"`
	ContentURL  *string         `json:"contentUrl"`
	Content     json.RawMessage `json:"content"`
}

// teamsCard leaves element properties free-form, as the Adaptive Card schema does.
type teamsCard struct {
	Schema  string           `json:"$schema"`
	Type    string           `json:"type"`
	Version string           `json:"version"`
	MSTeams map[string]any   `json:"msteams"`
	Body    []map[string]any `json:"body"`
	Actions []map[string]any `json:"actions"`
}

// teamsWebhook is a strict fake of a Workflows trigger, answering 202 like the real one.
type teamsWebhook struct {
	cards    []teamsCard
	rejected []string
	status   int
	mu       sync.Mutex
}

func (s *teamsWebhook) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func(status int, reason string) {
		s.rejected = append(s.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
	}
	if req.URL.Path != teamsPath {
		reject(http.StatusNotFound, "unknown workflow path")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	query := req.URL.Query()
	if query.Get("sig") != teamsSignature || query.Get("api-version") != "2016-06-01" {
		reject(http.StatusUnauthorized, "missing or wrong signature")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || len(body) > 28*1024 {
		reject(http.StatusRequestEntityTooLarge, "message over 28 KB")
		return
	}
	var msg teamsMessage
	if err := teamsDecode(body, &msg); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	if msg.Type != "message" || len(msg.Attachments) != 1 {
		reject(http.StatusBadRequest, "want one attachment in a message")
		return
	}
	att := msg.Attachments[0]
	if att.ContentType != "application/vnd.microsoft.card.adaptive" || att.ContentURL != nil {
		reject(http.StatusBadRequest, "not an Adaptive Card attachment")
		return
	}
	var card teamsCard
	if err := teamsDecode(att.Content, &card); err != nil {
		reject(http.StatusBadRequest, "card: "+err.Error())
		return
	}
	if card.Type != "AdaptiveCard" || card.Version == "" || len(card.Body) == 0 {
		reject(http.StatusBadRequest, "invalid Adaptive Card")
		return
	}
	s.cards = append(s.cards, card)
	w.WriteHeader(s.status)
}

func teamsDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func (s *teamsWebhook) snapshot() (cards []teamsCard, rejected []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]teamsCard(nil), s.cards...), append([]string(nil), s.rejected...)
}

func startTeams(t *testing.T, status int) (*teamsWebhook, *sidekick) {
	t.Helper()
	hook := &teamsWebhook{status: status}
	server := httptest.NewServer(hook)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf(`teams:
  host: %q
  secret_endpoint: %q
  query_params:
    api-version:
      values: ["2016-06-01"]
    sig:
      secrets: [%q]
`, server.URL, teamsPath, teamsSignature))
	return hook, sk
}

func teamsTexts(elements []map[string]any, texts []string, facts map[string]string) []string {
	for _, e := range elements {
		if text, ok := e["text"].(string); ok {
			texts = append(texts, text)
		}
		if list, ok := e["facts"].([]any); ok {
			for _, raw := range list {
				f, _ := raw.(map[string]any)
				title, _ := f["title"].(string)
				value, _ := f["value"].(string)
				facts[title] = value
			}
		}
		for _, key := range []string{"items", "columns"} {
			if nested, ok := e[key].([]any); ok {
				children := make([]map[string]any, 0, len(nested))
				for _, n := range nested {
					if m, ok := n.(map[string]any); ok {
						children = append(children, m)
					}
				}
				texts = teamsTexts(children, texts, facts)
			}
		}
	}
	return texts
}

func TestTeamsDeliversEvent(t *testing.T) {
	hook, sk := startTeams(t, http.StatusAccepted)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "teams", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	cards, rejected := hook.snapshot()
	require.Empty(t, rejected)
	require.Len(t, cards, 1)
	facts := map[string]string{}
	texts := teamsTexts(cards[0].Body, nil, facts)
	assert.Contains(t, texts, "e2e event "+marker)
	assert.Equal(t, "E2E "+marker, facts["rule"])
	assert.Equal(t, "warning", facts["priority"])
	assert.Equal(t, marker, facts["e2e.marker"])
	assert.Equal(t, "e2e", facts["tags"])
	assert.NotContains(t, sk.logs.String(), teamsSignature)
}

func TestTeamsReportsRejectedSignature(t *testing.T) {
	hook, sk := startTeams(t, http.StatusUnauthorized)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "teams", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 401")
	assert.NotContains(t, st.LastError, teamsSignature)
	assert.NotContains(t, sk.logs.String(), teamsSignature)

	cards, rejected := hook.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, cards, 1, "max_attempts 1 sends exactly once")
}

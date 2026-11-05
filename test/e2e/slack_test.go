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
	slackSecretToken = "e2eSecretToken"
	slackSecretPath  = "/services/T0E2E/B0E2E/" + slackSecretToken
)

// slackMessage mirrors the documented incoming webhook payload:
// https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks
// https://docs.slack.dev/messaging/formatting-message-text#when-to-use-attachments
type slackMessage struct {
	Mrkdwn      *bool             `json:"mrkdwn"`
	Text        string            `json:"text"`
	ThreadTS    string            `json:"thread_ts"`
	Blocks      json.RawMessage   `json:"blocks"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Fallback   string          `json:"fallback"`
	Color      string          `json:"color"`
	Pretext    string          `json:"pretext"`
	AuthorName string          `json:"author_name"`
	AuthorLink string          `json:"author_link"`
	AuthorIcon string          `json:"author_icon"`
	Title      string          `json:"title"`
	TitleLink  string          `json:"title_link"`
	Text       string          `json:"text"`
	Fields     []slackField    `json:"fields"`
	ImageURL   string          `json:"image_url"`
	ThumbURL   string          `json:"thumb_url"`
	Footer     string          `json:"footer"`
	FooterIcon string          `json:"footer_icon"`
	TS         json.Number     `json:"ts"`
	MrkdwnIn   []string        `json:"mrkdwn_in"`
	Blocks     json.RawMessage `json:"blocks"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// slackWebhook is a strict fake of a Slack incoming webhook. Valid payloads
// are recorded and answered with status and reply; any request Slack would
// reject is recorded with its reason and answered the way Slack answers it.
type slackWebhook struct {
	reply    string
	messages []slackMessage
	rejected []string
	status   int
	mu       sync.Mutex
}

func (s *slackWebhook) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func(status int, body, reason string) {
		s.rejected = append(s.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	if req.URL.Path != slackSecretPath {
		reject(http.StatusNotFound, "no_service", "unknown webhook path")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "invalid_method", "method not allowed")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "invalid_payload", "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var msg slackMessage
	if err := dec.Decode(&msg); err != nil {
		reject(http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}
	if dec.More() {
		reject(http.StatusBadRequest, "invalid_payload", "trailing data")
		return
	}
	if msg.Text == "" && len(msg.Blocks) == 0 && len(msg.Attachments) == 0 {
		reject(http.StatusBadRequest, "no_text", "empty message")
		return
	}
	s.messages = append(s.messages, msg)
	w.WriteHeader(s.status)
	_, _ = io.WriteString(w, s.reply)
}

func (s *slackWebhook) snapshot() (messages []slackMessage, rejected []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]slackMessage(nil), s.messages...), append([]string(nil), s.rejected...)
}

func startSlack(t *testing.T, status int, reply string) (*slackWebhook, *sidekick) {
	t.Helper()
	hook := &slackWebhook{status: status, reply: reply}
	server := httptest.NewServer(hook)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf("slack:\n  host: %q\n  secret_endpoint: %q\n", server.URL, slackSecretPath))
	return hook, sk
}

func TestSlackDeliversEvent(t *testing.T) {
	hook, sk := startSlack(t, http.StatusOK, "ok")

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "slack", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	messages, rejected := hook.snapshot()
	require.Empty(t, rejected)
	require.Len(t, messages, 1)
	require.Len(t, messages[0].Attachments, 1)
	attachment := messages[0].Attachments[0]
	assert.Equal(t, "e2e event "+marker, attachment.Fallback)
	assert.Equal(t, "e2e event "+marker, attachment.Text)
	assert.NotEmpty(t, attachment.Color)
	fields := make(map[string]string, len(attachment.Fields))
	for _, f := range attachment.Fields {
		fields[f.Title] = f.Value
	}
	assert.Equal(t, "E2E "+marker, fields["rule"])
	assert.Equal(t, "warning", fields["priority"])
	assert.Equal(t, marker, fields["e2e.marker"])
}

func TestSlackReportsNoService(t *testing.T) {
	hook, sk := startSlack(t, http.StatusNotFound, "no_service")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "slack", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 404")
	assert.NotContains(t, st.LastError, slackSecretToken)
	assert.NotContains(t, sk.logs.String(), slackSecretToken)

	messages, rejected := hook.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, messages, 1, "max_attempts 1 sends exactly once")
}

func TestSlackReportsInvalidPayload(t *testing.T) {
	hook, sk := startSlack(t, http.StatusBadRequest, "invalid_payload")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "slack", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 400")

	messages, rejected := hook.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, messages, 1, "max_attempts 1 sends exactly once")
}

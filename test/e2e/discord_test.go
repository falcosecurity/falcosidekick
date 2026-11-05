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
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	discordToken = "e2eDiscordToken"
	discordPath  = "/api/webhooks/123456789012345678/" + discordToken
)

// discordExecute mirrors the Execute Webhook JSON params:
// https://docs.discord.com/developers/resources/webhook
type discordExecute struct {
	Content         *string           `json:"content"`
	Username        *string           `json:"username"`
	AvatarURL       *string           `json:"avatar_url"`
	TTS             *bool             `json:"tts"`
	Flags           *int              `json:"flags"`
	ThreadName      *string           `json:"thread_name"`
	AllowedMentions json.RawMessage   `json:"allowed_mentions"`
	Components      json.RawMessage   `json:"components"`
	Attachments     json.RawMessage   `json:"attachments"`
	AppliedTags     json.RawMessage   `json:"applied_tags"`
	Poll            json.RawMessage   `json:"poll"`
	Embeds          []discordEmbedObj `json:"embeds"`
}

// discordEmbedObj mirrors the embed object:
// https://docs.discord.com/developers/resources/message
type discordEmbedObj struct {
	Title       string              `json:"title"`
	Type        string              `json:"type"`
	Description string              `json:"description"`
	URL         string              `json:"url"`
	Timestamp   string              `json:"timestamp"`
	Color       *int                `json:"color"`
	Footer      json.RawMessage     `json:"footer"`
	Image       json.RawMessage     `json:"image"`
	Thumbnail   json.RawMessage     `json:"thumbnail"`
	Video       json.RawMessage     `json:"video"`
	Provider    json.RawMessage     `json:"provider"`
	Author      json.RawMessage     `json:"author"`
	Fields      []discordEmbedField `json:"fields"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// discordWebhook is a strict fake of a Discord webhook that enforces embed limits and wait=true.
type discordWebhook struct {
	messages  []discordExecute
	rejected  []string
	status    int
	getStatus int
	gets      int
	mu        sync.Mutex
}

func (s *discordWebhook) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func(status int, reason string) {
		s.rejected = append(s.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"message": "rejected", "code": 50035}`)
	}
	if req.URL.Path != discordPath {
		reject(http.StatusNotFound, "unknown webhook path")
		return
	}
	if req.Method == http.MethodGet {
		s.gets++
		w.WriteHeader(s.getStatus)
		if s.getStatus == http.StatusOK {
			_, _ = io.WriteString(w, `{"type": 1, "id": "123456789012345678", "token": "`+discordToken+`"}`)
		}
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if req.URL.Query().Get("wait") != "true" {
		reject(http.StatusBadRequest, "wait=true missing: delivery would be unconfirmed")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var msg discordExecute
	if err := dec.Decode(&msg); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	if dec.More() {
		reject(http.StatusBadRequest, "trailing data")
		return
	}
	if reason := discordLimits(&msg); reason != "" {
		reject(http.StatusBadRequest, reason)
		return
	}
	s.messages = append(s.messages, msg)
	w.WriteHeader(s.status)
	if s.status == http.StatusOK {
		_, _ = io.WriteString(w, `{"id": "1", "type": 0, "channel_id": "2"}`)
	}
}

func discordLimits(msg *discordExecute) string {
	if (msg.Content == nil || *msg.Content == "") && len(msg.Embeds) == 0 {
		return "empty message"
	}
	if msg.Content != nil && utf8.RuneCountInString(*msg.Content) > 2000 {
		return "content over 2000 characters"
	}
	if len(msg.Embeds) > 10 {
		return "more than 10 embeds"
	}
	total := 0
	for i := range msg.Embeds {
		e := &msg.Embeds[i]
		if utf8.RuneCountInString(e.Title) > 256 || utf8.RuneCountInString(e.Description) > 4096 {
			return "embed title or description too long"
		}
		if len(e.Fields) > 25 {
			return "more than 25 fields"
		}
		total += utf8.RuneCountInString(e.Title) + utf8.RuneCountInString(e.Description)
		for _, f := range e.Fields {
			if f.Name == "" || f.Value == "" {
				return "empty field name or value"
			}
			if utf8.RuneCountInString(f.Name) > 256 || utf8.RuneCountInString(f.Value) > 1024 {
				return "field too long"
			}
			total += utf8.RuneCountInString(f.Name) + utf8.RuneCountInString(f.Value)
		}
	}
	if total > 6000 {
		return "embeds over 6000 characters"
	}
	return ""
}

func (s *discordWebhook) snapshot() (messages []discordExecute, rejected []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]discordExecute(nil), s.messages...), append([]string(nil), s.rejected...)
}

func newDiscord(t *testing.T, getStatus, status int) (hook *discordWebhook, outputs string) {
	t.Helper()
	hook = &discordWebhook{status: status, getStatus: getStatus}
	server := httptest.NewServer(hook)
	t.Cleanup(server.Close)
	return hook, fmt.Sprintf("discord:\n  host: %q\n  secret_endpoint: %q\n", server.URL, discordPath)
}

func startDiscord(t *testing.T, status int) (*discordWebhook, *sidekick) {
	t.Helper()
	hook, outputs := newDiscord(t, http.StatusOK, status)
	sk := startSidekick(t, outputs)
	return hook, sk
}

func TestDiscordDeliversEvent(t *testing.T) {
	hook, sk := startDiscord(t, http.StatusOK)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "discord", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	messages, rejected := hook.snapshot()
	require.Empty(t, rejected)
	require.Len(t, messages, 1)
	hook.mu.Lock()
	assert.Equal(t, 1, hook.gets, "startup reads the webhook once")
	hook.mu.Unlock()
	require.Len(t, messages[0].Embeds, 1)
	require.NotNil(t, messages[0].AvatarURL)
	embed := messages[0].Embeds[0]
	assert.Equal(t, "e2e event "+marker, embed.Description)
	require.NotNil(t, embed.Color)
	assert.Equal(t, 12745742, *embed.Color)
	fields := make(map[string]string, len(embed.Fields))
	for _, f := range embed.Fields {
		fields[f.Name] = f.Value
	}
	assert.Equal(t, "E2E "+marker, fields["rule"])
	assert.Equal(t, "warning", fields["priority"])
	assert.Equal(t, "```"+marker+"```", fields["e2e.marker"])
	assert.Equal(t, "e2e", fields["tags"])
	assert.NotContains(t, sk.logs.String(), discordToken)
}

// The health check only reads the webhook, so a rejected token stops startup before any post.
func TestDiscordInvalidTokenFailsStartup(t *testing.T) {
	hook, outputs := newDiscord(t, http.StatusUnauthorized, http.StatusUnauthorized)
	logs := startSidekickFails(t, outputs)
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 401")
	assert.NotContains(t, logs, discordToken)

	messages, rejected := hook.snapshot()
	assert.Empty(t, rejected)
	assert.Empty(t, messages)
}

func TestDiscordReportsDeliveryFailure(t *testing.T) {
	hook, sk := startDiscord(t, http.StatusInternalServerError)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "discord", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 500")
	assert.NotContains(t, st.LastError, discordToken)
	assert.NotContains(t, sk.logs.String(), discordToken)

	messages, rejected := hook.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, messages, 1, "max_attempts 1 sends exactly once")
}

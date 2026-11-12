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
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mailpit with SMTP auth and STARTTLS, its certificate issued for the SMTP host.
const (
	envSMTPAddr     = "FALCOSIDEKICK_E2E_SMTP_ADDR"
	envSMTPUser     = "FALCOSIDEKICK_E2E_SMTP_USER"
	envSMTPPassword = "FALCOSIDEKICK_E2E_SMTP_PASSWORD"
	envMailpitAPI   = "FALCOSIDEKICK_E2E_MAILPIT_API"

	smtpFrom = "falco@e2e.example"
	smtpTo   = "secops@e2e.example"
)

type mailpitTarget struct {
	host     string
	port     string
	user     string
	password string
	api      string
	caFile   string
}

func mailpit(t *testing.T) *mailpitTarget {
	t.Helper()
	addr := requireEnv(t, envSMTPAddr)
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return &mailpitTarget{
		host:     host,
		port:     port,
		user:     requireEnv(t, envSMTPUser),
		password: requireEnv(t, envSMTPPassword),
		api:      strings.TrimSuffix(requireEnv(t, envMailpitAPI), "/"),
		caFile:   serverCertificate(t, addr, host),
	}
}

// serverCertificate writes the STARTTLS certificate as a trust anchor.
func serverCertificate(t *testing.T, addr, host string) string {
	t.Helper()
	client, err := smtp.Dial(addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}))
	state, ok := client.TLSConnectionState()
	require.True(t, ok)
	path := filepath.Join(t.TempDir(), "mailpit.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.PeerCertificates[0].Raw}), 0o600))
	_ = client.Quit()
	return path
}

func (m *mailpitTarget) output(password, caFile, extra string) string {
	return fmt.Sprintf("smtp:\n  host: %q\n  port: %s\n  username: %q\n  password: %q\n  from: %q\n  to: [%q]\n  tls:\n    ca_file: %q\n",
		m.host, m.port, m.user, password, "Falco E2E <"+smtpFrom+">", smtpTo, caFile) + indent(extra)
}

// mailpitMessage is the subset of GET /api/v1/message/{ID} that the tests read:
// https://mailpit.axllent.org/docs/api-v1/view.html#get-/api/v1/message/-ID-
type mailpitMessage struct {
	From    mailpitAddress   `json:"From"`
	ID      string           `json:"ID"`
	Subject string           `json:"Subject"`
	Text    string           `json:"Text"`
	HTML    string           `json:"HTML"`
	To      []mailpitAddress `json:"To"`
}

type mailpitAddress struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

func (m *mailpitTarget) get(t *testing.T, path string, into any) {
	t.Helper()
	resp, err := httpDo(http.MethodGet, m.api+path, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, path)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(into))
}

func (m *mailpitTarget) waitMessage(t *testing.T, marker string) mailpitMessage {
	t.Helper()
	var search struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	eventuallyf(t, func() bool {
		m.get(t, "/api/v1/search?query="+url.QueryEscape(marker), &search)
		return len(search.Messages) > 0
	}, "mail with %s", marker)
	require.Len(t, search.Messages, 1, "one email per event")
	var msg mailpitMessage
	m.get(t, "/api/v1/message/"+search.Messages[0].ID, &msg)
	return msg
}

func TestSMTPDeliversEvent(t *testing.T) {
	target := mailpit(t)
	sk := startSidekick(t, target.output(target.password, target.caFile, ""))
	marker := newMarker(t)
	sk.postEvent(t, marker)

	msg := target.waitMessage(t, marker)
	assert.Equal(t, mailpitAddress{Name: "Falco E2E", Address: smtpFrom}, msg.From)
	assert.Equal(t, []mailpitAddress{{Address: smtpTo}}, msg.To)
	assert.Equal(t, "[Warning] E2E "+marker+" on e2e-host", msg.Subject)
	assert.Contains(t, msg.Text, "Rule:     E2E "+marker)
	assert.Contains(t, msg.Text, "e2e.marker: "+marker)
	assert.Contains(t, msg.HTML, ">E2E "+marker+"</h1>")

	st := sk.waitStatus(t, "smtp", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.NotContains(t, sk.logs.String(), target.password)
}

func TestSMTPTextFormat(t *testing.T) {
	target := mailpit(t)
	sk := startSidekick(t, target.output(target.password, target.caFile, "format: text\n"))
	marker := newMarker(t)
	sk.postEvent(t, marker)

	msg := target.waitMessage(t, marker)
	assert.Empty(t, msg.HTML)
	assert.Contains(t, msg.Text, "e2e.marker: "+marker)
}

func TestSMTPWrongPasswordStartsDegraded(t *testing.T) {
	target := mailpit(t)
	wrong := "wrong-" + newMarker(t)
	_, logs := startSidekickDegraded(t, "smtp", target.output(wrong, target.caFile, ""))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "smtp connect: server replied 535")
	assert.NotContains(t, logs, wrong)
}

func TestSMTPUnknownCAStartsDegraded(t *testing.T) {
	target := mailpit(t)
	_, logs := startSidekickDegraded(t, "smtp", target.output(target.password, writeUnknownCA(t), ""))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "TLS certificate verification failed")
	assert.NotContains(t, logs, target.password)
}

func TestSMTPReportsUnreachableServer(t *testing.T) {
	target := mailpit(t)
	target.port = fmt.Sprint(freePort(t))
	sk := startSidekick(t, target.output(target.password, target.caFile, ""))
	st := sk.status(t, "smtp")
	assert.Equal(t, "degraded", st.Status, "an unreachable server at startup is transient")
	assert.Contains(t, st.LastWarning, "smtp connect: connection refused")
}

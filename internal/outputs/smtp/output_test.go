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

package smtp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gosmtp "github.com/wneessen/go-mail/smtp"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testPassword = "s3cret-Pa55"
	testToken    = "tok-0123456789"
	localhostIP  = "127.0.0.1"
)

func baseConfig() map[string]any {
	return map[string]any{
		"host":     "mail.example",
		"user":     "falco",
		"password": testPassword,
		"from":     "Falco <falco@example.com>",
		"to":       []string{"secops@example.com", "Ops Team <ops@example.com>"},
	}
}

func with(cfg map[string]any, kv ...any) map[string]any {
	out := maps.Clone(cfg)
	for i := 0; i < len(kv); i += 2 {
		key := kv[i].(string)
		if kv[i+1] == nil {
			delete(out, key)
			continue
		}
		out[key] = kv[i+1]
	}
	return out
}

func newTestDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d.(*driver)
}

// serverConfig targets srv over STARTTLS with a trusted certificate.
func serverConfig(t *testing.T, srv *fakeServer, kv ...any) map[string]any {
	t.Helper()
	cfg := with(baseConfig(), "host", localhostIP, "port", srv.port(), "tls", map[string]any{"ca_file": caFile(t)})
	return with(cfg, kv...)
}

func TestValidation(t *testing.T) {
	base := baseConfig()
	xoauth2 := with(base, "auth_mechanism", "xoauth2", "password", nil, "token", testToken)
	tests := []struct {
		config map[string]any
		name   string
		want   string
	}{
		{name: "minimal", config: base},
		{name: "missing host", config: with(base, "host", nil), want: "host: is required"},
		{name: "host with port", config: with(base, "host", "mail:587"), want: "host: must be a host name"},
		{name: "host with scheme", config: with(base, "host", "smtp://mail"), want: "host: must be a host name"},
		{name: "bad port", config: with(base, "port", 0x10000), want: "port: must be between 1 and 65535"},
		{name: "bad tls_mode", config: with(base, "tls_mode", "ssl"), want: `tls_mode: must be starttls/implicit/opportunistic/none`},
		{name: "missing from", config: with(base, "from", nil), want: "from: is required"},
		{name: "bad from", config: with(base, "from", "not an address"), want: "from: must be one RFC 5322 address"},
		{name: "header injection in from", config: with(base, "from", "a@b.c\r\nBcc: x@y.z"), want: "from"},
		{name: "missing to", config: with(base, "to", nil), want: "to: is required"},
		{name: "comma list", config: with(base, "to", "a@example.com, b@example.com"), want: "to[0]: must be one RFC 5322 address"},
		{name: "bad to", config: with(base, "to", []string{"ok@example.com", "nope"}), want: "to[1]"},
		{name: "plain without password", config: with(base, "password", nil), want: "password: is required with auth_mechanism plain"},
		{name: "plain without user", config: with(base, "user", nil), want: "user: is required with auth_mechanism plain"},
		{name: "unsupported mechanism", config: with(base, "auth_mechanism", "oauthbearer"), want: `auth_mechanism: must be plain/xoauth2/none`},
		{name: "none with credentials", config: with(base, "auth_mechanism", "none"), want: "password: is not used by auth_mechanism none"},
		{name: "none", config: with(base, "auth_mechanism", "none", "user", nil, "password", nil)},
		{name: "xoauth2", config: xoauth2},
		{name: "xoauth2 implicit", config: with(xoauth2, "tls_mode", "implicit")},
		{name: "xoauth2 without token", config: with(xoauth2, "token", nil), want: "token: is required"},
		{name: "xoauth2 with password", config: with(xoauth2, "password", testPassword), want: "password: is not used"},
		{name: "xoauth2 opportunistic", config: with(xoauth2, "tls_mode", "opportunistic"), want: "xoauth2 requires tls_mode starttls or implicit"},
		{name: "xoauth2 opportunistic on localhost", config: with(xoauth2, "tls_mode", "opportunistic", "host", "localhost")},
		{name: "control char", config: with(base, "user", "fal\nco"), want: "user: must not contain control characters"},
		{name: "plain without tls", config: with(base, "tls_mode", "none"), want: "auth_mechanism: plain requires TLS"},
		{name: "plain without tls on localhost", config: with(base, "tls_mode", "none", "host", "localhost")},
		{name: "tls block with none", config: with(base, "tls_mode", "none", "auth_mechanism", "none", "user", nil, "password", nil,
			"tls", map[string]any{"insecure_skip_verify": true}), want: "tls: is not used with tls_mode none"},
		{name: "missing ca", config: with(base, "tls", map[string]any{"ca_file": "/does/not/exist"}), want: "tls.ca_file"},
		{name: "bad format", config: with(base, "output_format", "markdown"), want: `output_format: must be html/text`},
		{name: "identity removed", config: with(base, "identity", "admin"), want: "identity"},
		{name: "v2 hostport", config: with(base, "hostport", "mail:25"), want: "hostport"},
		{name: "v2 tls bool", config: with(base, "tls", false), want: "tls"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := OutputType.New(tc.config, output.Deps{})
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, "smtp", d.Name())
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), testPassword)
			assert.NotContains(t, err.Error(), testToken)
		})
	}
}

func TestDefaults(t *testing.T) {
	tests := []struct {
		mode string
		port int
	}{{"", 587}, {"starttls", 587}, {"opportunistic", 587}, {"implicit", 465}, {"none", 25}}
	for _, tc := range tests {
		cfg := with(baseConfig(), "host", "localhost")
		if tc.mode != "" {
			cfg["tls_mode"] = tc.mode
		}
		d := newTestDriver(t, cfg)
		assert.Equal(t, tc.port, d.cfg.Port, tc.mode)
	}
	d := newTestDriver(t, with(baseConfig(), "runtime", map[string]any{"workers": 3}))
	assert.Equal(t, "starttls", d.cfg.TLSMode)
	assert.Equal(t, "plain", d.cfg.AuthMechanism)
	assert.Equal(t, "html", d.cfg.OutputFormat)
	assert.Equal(t, "mail.example", d.tlsConfig.ServerName)
	assert.Equal(t, 3, d.RuntimeConfig().Workers)
	require.Len(t, d.to, 2)
	assert.Equal(t, "ops@example.com", d.to[1].Address)
	require.NoError(t, d.Init(context.Background()))
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	assert.True(t, fields["password"].Secret)
	assert.True(t, fields["token"].Secret)
	assert.False(t, fields["user"].Secret)
	assert.True(t, fields["from"].Required)
	assert.True(t, fields["to"].Required)
	assert.Equal(t, "starttls", fields["tls_mode"].Default)
	assert.Equal(t, []string{"plain", "xoauth2", "none"}, fields["auth_mechanism"].Values)
	assert.Contains(t, fields, "tls.ca_file")
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func render(t *testing.T, d *driver, evt *event.Event) []byte {
	t.Helper()
	msg, err := d.message(evt)
	require.NoError(t, err)
	var buf bytes.Buffer
	_, err = msg.WriteTo(&buf)
	require.NoError(t, err)
	return buf.Bytes()
}

// parse reads the message and returns the decoded parts by media type.
func parse(t *testing.T, raw []byte) (msg *mail.Message, parts map[string]string) {
	t.Helper()
	for _, line := range strings.Split(string(raw), "\r\n") {
		assert.LessOrEqual(t, len(line), 998, "RFC 5322 line limit")
		assert.NotContains(t, line, "\n", "lines end with CRLF")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	require.NoError(t, err)
	parts = map[string]string{}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	require.NoError(t, err)
	if !strings.HasPrefix(mediaType, "multipart/") {
		assert.Equal(t, "quoted-printable", msg.Header.Get("Content-Transfer-Encoding"))
		body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
		require.NoError(t, err)
		parts[mediaType] = strings.ReplaceAll(string(body), "\r\n", "\n")
		return msg, parts
	}
	assert.Equal(t, "multipart/alternative", mediaType)
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		partType, partParams, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		require.NoError(t, err)
		assert.Equal(t, "utf-8", strings.ToLower(partParams["charset"]))
		assert.Equal(t, "quoted-printable", part.Header.Get("Content-Transfer-Encoding"))
		body, err := io.ReadAll(quotedprintable.NewReader(part))
		require.NoError(t, err)
		parts[partType] = strings.ReplaceAll(string(body), "\r\n", "\n")
	}
	return msg, parts
}

func TestHTMLMessage(t *testing.T) {
	d := newTestDriver(t, baseConfig())
	evt := testutil.CreateValidEvent()
	evt.Output = `<script>alert("x")</script> opened /bin/hack`
	evt.OutputFields["proc.cmdline"] = strings.Repeat("long ", 400)

	msg, parts := parse(t, render(t, d, evt))
	from, err := msg.Header.AddressList("From")
	require.NoError(t, err)
	assert.Equal(t, []*mail.Address{{Name: "Falco", Address: "falco@example.com"}}, from)
	to, err := msg.Header.AddressList("To")
	require.NoError(t, err)
	require.Len(t, to, 2)
	assert.Equal(t, "ops@example.com", to[1].Address)
	subject, err := (&mime.WordDecoder{}).DecodeHeader(msg.Header.Get("Subject"))
	require.NoError(t, err)
	assert.Equal(t, `[Error] <script>alert("x")</script> opened /bin/hack`, subject)
	date, err := msg.Header.Date()
	require.NoError(t, err)
	assert.True(t, evt.Time.Equal(date))
	assert.Regexp(t, `^<[^@<>\s]+@[^@<>\s]+>$`, msg.Header.Get("Message-ID"))
	assert.Equal(t, "1.0", msg.Header.Get("MIME-Version"))
	assert.Equal(t, "auto-generated", msg.Header.Get("Auto-Submitted"))

	require.Len(t, parts, 2)
	text := parts["text/plain"]
	assert.Contains(t, text, "Rule:     Write below binary dir")
	assert.Contains(t, text, "Hostname: node-1")
	assert.Contains(t, text, "Time:     2026-04-01T10:30:00Z")
	assert.Contains(t, text, "Tags:     filesystem, mitre_persistence")
	assert.Contains(t, text, "  fd.name: /bin/hack\n  proc.cmdline: long")

	html := parts["text/html"]
	assert.Contains(t, html, "border-top:6px solid #e20b0b", "priority color")
	assert.Contains(t, html, "&lt;script&gt;", "output is escaped")
	assert.NotContains(t, html, "<script>")
	assert.Contains(t, html, ">fd.name</th>")
	assert.NotContains(t, html, "ZgotmplZ")
}

func TestTextMessage(t *testing.T) {
	d := newTestDriver(t, with(baseConfig(), "output_format", "text"))
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	evt.Tags = nil
	evt.OutputFields = nil
	msg, parts := parse(t, render(t, d, evt))
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	require.NoError(t, err)
	assert.Equal(t, "text/plain", mediaType)
	assert.Equal(t, "utf-8", strings.ToLower(params["charset"]))
	text := parts["text/plain"]
	assert.NotContains(t, text, "Hostname:")
	assert.NotContains(t, text, "Tags:")
	assert.NotContains(t, text, "Output fields:")
	assert.True(t, strings.HasPrefix(text, "Error: File below a known binary directory opened for writing\n"), text)
}

func TestSubjectEncoding(t *testing.T) {
	d := newTestDriver(t, baseConfig())
	evt := testutil.CreateValidEvent()
	evt.Output = "naïve\r\nBcc: attacker@example.com " + strings.Repeat("é", 400)
	msg, _ := parse(t, render(t, d, evt))
	assert.Empty(t, msg.Header.Get("Bcc"), "no header injection")
	subject, err := (&mime.WordDecoder{}).DecodeHeader(msg.Header.Get("Subject"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(subject, "[Error] naïve"), subject)
	assert.True(t, strings.HasSuffix(subject, "..."))
	assert.LessOrEqual(t, len([]rune(subject)), maxSubjectRunes)
}

func TestPriorityColor(t *testing.T) {
	d := newTestDriver(t, baseConfig())
	evt := testutil.CreateValidEvent()
	evt.Priority = event.PriorityWarning
	_, parts := parse(t, render(t, d, evt))
	assert.Contains(t, parts["text/html"], "solid #ffc700")
}

func TestSendDelivers(t *testing.T) {
	srv := newFakeServer(t, nil)
	d := newTestDriver(t, serverConfig(t, srv))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))

	sessions := srv.recorded()
	require.Len(t, sessions, 1)
	s := sessions[0]
	assert.True(t, s.tls, "STARTTLS before AUTH")
	assert.Equal(t, []string{"PLAIN \x00falco\x00" + testPassword}, s.auth)
	assert.True(t, strings.HasPrefix(s.from, "FROM:<falco@example.com>"), s.from)
	require.Len(t, s.rcpt, 2)
	assert.True(t, strings.HasPrefix(s.rcpt[0], "TO:<secops@example.com>"))
	assert.True(t, strings.HasPrefix(s.rcpt[1], "TO:<ops@example.com>"))
	assert.True(t, s.quit)
	_, parts := parse(t, []byte(s.data))
	assert.Contains(t, parts["text/plain"], "Write below binary dir")
	assert.True(t, strings.HasPrefix(s.commands[0], "EHLO "))
}

func TestHealthCheckSendsNoMail(t *testing.T) {
	srv := newFakeServer(t, nil)
	d := newTestDriver(t, serverConfig(t, srv))
	require.NoError(t, d.HealthCheck(context.Background()))
	s := srv.recorded()[0]
	assert.Empty(t, s.from)
	assert.Empty(t, s.data)
	assert.Len(t, s.auth, 1)
	assert.True(t, s.quit)
}

func TestImplicitTLS(t *testing.T) {
	srv := newFakeServer(t, func(s *fakeServer) { s.implicitTLS = true })
	d := newTestDriver(t, serverConfig(t, srv, "tls_mode", "implicit"))
	require.NoError(t, d.HealthCheck(context.Background()))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	for _, s := range srv.recorded() {
		assert.True(t, s.tls)
		assert.NotContains(t, s.commands, "STARTTLS")
		assert.Len(t, s.auth, 1)
	}
}

func TestOpportunisticWithoutStartTLS(t *testing.T) {
	srv := newFakeServer(t, func(s *fakeServer) { s.noStartTLS = true })
	d := newTestDriver(t, serverConfig(t, srv, "tls_mode", "opportunistic", "auth_mechanism", "none", "user", nil, "password", nil))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	s := srv.recorded()[0]
	assert.False(t, s.tls)
	assert.Empty(t, s.auth)
}

func TestNoTLSToLocalhost(t *testing.T) {
	srv := newFakeServer(t, nil)
	d := newTestDriver(t, serverConfig(t, srv, "tls_mode", "none", "tls", nil))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	s := srv.recorded()[0]
	assert.False(t, s.tls)
	assert.NotContains(t, s.commands, "STARTTLS")
	assert.Len(t, s.auth, 1, "PLAIN is allowed in clear to localhost only")
}

func TestXOAuth2(t *testing.T) {
	srv := newFakeServer(t, nil)
	d := newTestDriver(t, serverConfig(t, srv, "auth_mechanism", "xoauth2", "password", nil, "token", testToken))
	require.NoError(t, d.HealthCheck(context.Background()))
	auth := srv.recorded()[0].auth
	require.NotEmpty(t, auth)
	assert.Equal(t, "XOAUTH2 user=falco\x01auth=Bearer "+testToken+"\x01\x01", auth[0])
}

func TestRejectedCredentialsAreMisconfigured(t *testing.T) {
	tests := []struct {
		reply      func(string, []byte) []string
		name       string
		wantClient string
		wantCode   string
		options    []any
		misconfig  bool
	}{
		{name: "535", reply: func(string, []byte) []string { return []string{"535 5.7.8 bad " + testPassword} }, wantCode: "535", misconfig: true},
		{name: "534", reply: func(string, []byte) []string { return []string{"534 5.7.9 too weak"} }, wantCode: "534", misconfig: true},
		{name: "454 transient", reply: func(string, []byte) []string { return []string{"454 4.7.0 try later"} }, wantCode: "454"},
		{
			name:    "xoauth2 error challenge",
			options: []any{"auth_mechanism", "xoauth2", "password", nil, "token", testToken},
			reply: func(string, []byte) []string {
				return []string{"334 eyJzdGF0dXMiOiI0MDEifQ==", "535 5.7.8 rejected"}
			},
			wantCode: "535", misconfig: true, wantClient: "client: ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, func(s *fakeServer) { s.authReply = tc.reply })
			d := newTestDriver(t, serverConfig(t, srv, tc.options...))
			err := d.HealthCheck(context.Background())
			require.Error(t, err)
			assert.Equal(t, tc.misconfig, errors.Is(err, output.ErrMisconfigured))
			assert.Contains(t, err.Error(), "smtp connect: server replied "+tc.wantCode)
			assert.NotContains(t, err.Error(), testPassword)
			assert.NotContains(t, err.Error(), testToken)
			assert.NotContains(t, err.Error(), "bad", "server text is dropped")
			if tc.wantClient != "" {
				assert.Contains(t, srv.recorded()[0].auth, tc.wantClient)
			}

			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.NotContains(t, err.Error(), testPassword)
		})
	}
}

func TestServerCapabilities(t *testing.T) {
	misconfigured := []struct {
		configure func(*fakeServer)
		name      string
		want      string
		options   []any
	}{
		{name: "starttls required but missing", configure: func(s *fakeServer) { s.noStartTLS = true }, want: "server does not offer STARTTLS"},
		{name: "auth missing", configure: func(s *fakeServer) { s.noAuth = true }, want: "server does not offer AUTH"},
		{name: "plain not offered", configure: func(s *fakeServer) { s.mechanisms = "LOGIN" }, want: "server does not offer the auth mechanism"},
		{
			name: "xoauth2 not offered", configure: func(s *fakeServer) { s.mechanisms = "PLAIN" }, want: "server does not offer the auth mechanism",
			options: []any{"auth_mechanism", "xoauth2", "password", nil, "token", testToken},
		},
		{name: "untrusted certificate", options: []any{"tls", nil}, want: "TLS certificate verification failed"},
	}
	for _, tc := range misconfigured {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, tc.configure)
			d := newTestDriver(t, serverConfig(t, srv, tc.options...))
			err := d.HealthCheck(context.Background())
			require.ErrorIs(t, err, output.ErrMisconfigured)
			assert.Contains(t, err.Error(), tc.want)
			for _, s := range srv.recorded() {
				assert.Empty(t, s.auth, "no credentials sent")
			}
		})
	}

	t.Run("credentials without tls to a remote host", func(t *testing.T) {
		err := markMisconfigured(newDeliveryError(context.Background(), shared.OpConnect, fmt.Errorf("SMTP AUTH failed: %w", gosmtp.ErrUnencrypted)))
		require.ErrorIs(t, err, output.ErrMisconfigured)
		assert.Equal(t, "smtp connect: authentication requires TLS", err.Error())
	})
	t.Run("recipient rejected", func(t *testing.T) {
		srv := newFakeServer(t, func(s *fakeServer) { s.rcptReply = "550 5.1.1 no such user secops@example.com" })
		d := newTestDriver(t, serverConfig(t, srv))
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.Equal(t, "smtp rcpt: server replied 550", err.Error())
		assert.True(t, output.IsPermanent(err), "5yz is a permanent negative completion")
	})
	t.Run("recipient deferred", func(t *testing.T) {
		srv := newFakeServer(t, func(s *fakeServer) { s.rcptReply = "451 4.3.0 try again later" })
		d := newTestDriver(t, serverConfig(t, srv))
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.Equal(t, "smtp rcpt: server replied 451", err.Error())
		assert.False(t, output.IsPermanent(err), "4yz is a transient negative completion")
	})
}

func TestUnreachableIsTransient(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, ln.Close())
	d := newTestDriver(t, with(baseConfig(), "host", localhostIP, "port", port))
	err = d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "smtp connect: connection refused")

	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "smtp connect: connection refused")
}

// hangingServer returns the port of a server that never sends the greeting.
func hangingServer(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(testutil.HangingTCPServer(t))
	require.NoError(t, err)
	return port
}

func TestCancellation(t *testing.T) {
	for _, mode := range []string{"starttls", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			d := newTestDriver(t, with(baseConfig(), "host", localhostIP, "port", hangingServer(t), "tls_mode", mode))
			for name, call := range map[string]func(context.Context) error{
				"Send":        func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) },
				"HealthCheck": d.HealthCheck,
			} {
				err := testutil.RequireReturnsOnCancel(t, name, call)
				assert.NotErrorIs(t, err, output.ErrMisconfigured, name)
				assert.Contains(t, err.Error(), "timeout (deadline exceeded)", name)
			}
		})
	}
	t.Run("canceled during the session", func(t *testing.T) {
		d := newTestDriver(t, with(baseConfig(), "host", localhostIP, "port", hangingServer(t)))
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		err := d.HealthCheck(ctx)
		require.Error(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
		assert.Contains(t, err.Error(), "request canceled")
	})
	t.Run("expired context", func(t *testing.T) {
		d := newTestDriver(t, baseConfig())
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		err := d.Send(ctx, testutil.CreateValidEvent())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout (deadline exceeded)")
	})
}

func TestClose(t *testing.T) {
	d := newTestDriver(t, baseConfig())
	require.NoError(t, d.Close())
}

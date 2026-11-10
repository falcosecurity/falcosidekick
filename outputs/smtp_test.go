// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"expvar"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

// The Date header must be RFC 5322 compliant; otherwise receivers that normalize a
// malformed Date on inbound (e.g. Microsoft 365) rewrite it and break the DKIM
// signature, since Date is a signed header.
func TestNewSMTPPayloadDateHeaderIsRFC5322(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	config := &types.Configuration{}
	config.SMTP.From = "falco@localhost"
	config.SMTP.To = "alerts@localhost"
	config.SMTP.OutputFormat = Text

	payload := newSMTPPayload(f, config)

	// falcoTestInput time is 2001-01-01T01:10:00Z (a Monday) -> RFC 5322 / time.RFC1123Z form.
	require.Contains(t, payload.Body, "Date: Mon, 01 Jan 2001 01:10:00 +0000\n")
}

type smtpTestBackend struct {
	logouts chan struct{}
	data    chan string
}

func (b *smtpTestBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &smtpTestSession{backend: b}, nil
}

type smtpTestSession struct {
	backend *smtpTestBackend
}

func (s *smtpTestSession) Reset() {}

func (s *smtpTestSession) Logout() error {
	s.backend.logouts <- struct{}{}
	return nil
}

func (s *smtpTestSession) Mail(_ string, _ *smtp.MailOptions) error { return nil }

func (s *smtpTestSession) Rcpt(_ string, _ *smtp.RcptOptions) error { return nil }

func (s *smtpTestSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.data <- string(b)
	return nil
}

func TestSendMailClosesTheConnection(t *testing.T) {
	backend := &smtpTestBackend{logouts: make(chan struct{}, 1), data: make(chan string, 1)}
	server := smtp.NewServer(backend)
	server.Domain = "smtp.test"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(l) }()
	defer server.Close()

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	config := &types.Configuration{}
	config.SMTP.HostPort = l.Addr().String()
	config.SMTP.From = "falco@smtp.test"
	config.SMTP.To = "alerts@smtp.test"
	config.SMTP.OutputFormat = Text
	config.SMTP.AuthMechanism = None

	client := &Client{
		OutputType: "SMTP",
		Config:     config,
		Stats:      &types.Statistics{SMTP: expvar.NewMap("smtp_close_test")},
	}

	client.SendMail(f)

	select {
	case <-backend.data:
	case <-time.After(5 * time.Second):
		t.Fatal("the message was not delivered")
	}
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.SMTP, OK))

	select {
	case <-backend.logouts:
	case <-time.After(2 * time.Second):
		t.Fatal("SendMail returned without closing the SMTP connection")
	}
}

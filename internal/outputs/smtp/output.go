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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"
	gosmtp "github.com/wneessen/go-mail/smtp"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "smtp"

	tlsModeStartTLS      = "starttls"
	tlsModeOpportunistic = "opportunistic"
	tlsModeImplicit      = "implicit"
	tlsModeNone          = "none"

	formatHTML = "html"
	formatText = "text"

	portSubmission = 587
	portImplicit   = 465
	portRelay      = 25

	// sessionTimeout bounds one SMTP session when the context has no deadline.
	sessionTimeout = 30 * time.Second

	opQuit = "quit"
	opMail = "mail"
	opRcpt = "rcpt"
	opData = "data"

	codeNoStartTLS  = "server does not offer STARTTLS"
	codeNoAuth      = "server does not offer AUTH"
	codeNoMechanism = "server does not offer the auth mechanism"
	codeUnencrypted = "authentication requires TLS"
)

type config struct {
	TLS           shared.TLSClientConfig `mapstructure:"tls"`
	Host          string                 `mapstructure:"host"`
	TLSMode       string                 `mapstructure:"tls_mode"`
	AuthMechanism string                 `mapstructure:"auth_mechanism"`
	User          string                 `mapstructure:"user"`
	Password      string                 `mapstructure:"password"`
	Token         string                 `mapstructure:"token"`
	From          string                 `mapstructure:"from"`
	OutputFormat  string                 `mapstructure:"output_format"`
	To            []string               `mapstructure:"to"`
	Runtime       output.RuntimeConfig   `mapstructure:"runtime"`
	Port          int                    `mapstructure:"port"`
}

// OutputType describes the SMTP output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "email",
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "host", Type: "string", Required: true, Label: "Host"},
			{Name: "port", Type: "int", Label: "Port (587, 465 with implicit TLS, 25 without TLS)"},
			{
				Name: "tls_mode", Type: "enum", Values: []string{tlsModeStartTLS, tlsModeImplicit, tlsModeOpportunistic, tlsModeNone},
				Default: tlsModeStartTLS, Label: "TLS Mode",
			},
			{Name: "auth_mechanism", Type: "enum", Values: []string{authPlain, authXOAuth2, authNone}, Default: authPlain, Label: "SASL Mechanism"},
			{Name: "user", Type: "string", Label: "User"},
			{Name: "password", Type: "string", Secret: true, Label: "Password"},
			{Name: "token", Type: "string", Secret: true, Label: "OAuth 2.0 Access Token"},
			{Name: "from", Type: "string", Required: true, Label: "Sender Address"},
			{Name: "to", Type: "string[]", Required: true, Label: "Recipient Addresses"},
			{Name: "output_format", Type: "enum", Values: []string{formatHTML, formatText}, Default: formatHTML, Label: "Output Format"},
		}, append(shared.TLSClientSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	tlsConfig *tls.Config
	from      *netmail.Address
	options   []mail.Option
	to        []*netmail.Address
	cfg       config
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if literal := strings.TrimSuffix(strings.TrimPrefix(c.Host, "["), "]"); net.ParseIP(literal) != nil {
		c.Host = literal
	}
	switch {
	case c.Host == "":
		errs.Add("host", "is required")
	case net.ParseIP(c.Host) != nil:
	case strings.ContainsAny(c.Host, "/?#@:[] \t\r\n"):
		errs.Add("host", "must be a host name or IP address without scheme, port or path")
	}
	if c.TLSMode == "" {
		c.TLSMode = tlsModeStartTLS
	}
	switch c.TLSMode {
	case tlsModeStartTLS, tlsModeOpportunistic:
		c.defaultPort(portSubmission)
	case tlsModeImplicit:
		c.defaultPort(portImplicit)
	case tlsModeNone:
		c.defaultPort(portRelay)
		if c.TLS != (shared.TLSClientConfig{}) {
			errs.Add("tls", "is not used with tls_mode none")
		}
	default:
		errs.Add("tls_mode", "must be starttls/implicit/opportunistic/none")
	}
	if c.Port < 1 || c.Port > 65535 {
		errs.Add("port", "must be between 1 and 65535")
	}
	errs.Merge("", c.validateAuth())
	errs.Merge("", c.validateAddresses())
	if c.OutputFormat == "" {
		c.OutputFormat = formatHTML
	} else if c.OutputFormat != formatHTML && c.OutputFormat != formatText {
		errs.Add("output_format", "must be html/text")
	}
	errs.Merge("tls", c.TLS.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (c *config) defaultPort(port int) {
	if c.Port == 0 {
		c.Port = port
	}
}

func (c *config) validateAuth() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.AuthMechanism == "" {
		c.AuthMechanism = authPlain
	}
	// Each set field must be used by the mechanism, so a typo cannot drop a credential silently.
	var used map[string]bool
	switch c.AuthMechanism {
	case authPlain:
		used = map[string]bool{"user": true, "password": true}
		requireField(&errs, "user", c.User, authPlain)
		requireField(&errs, "password", c.Password, authPlain)
	case authXOAuth2:
		used = map[string]bool{"user": true, "token": true}
		requireField(&errs, "user", c.User, authXOAuth2)
		requireField(&errs, "token", c.Token, authXOAuth2)
	case authNone:
	default:
		errs.Add("auth_mechanism", "must be plain/xoauth2/none")
		return errs
	}
	for _, field := range []struct {
		name, value string
	}{{"user", c.User}, {"password", c.Password}, {"token", c.Token}} {
		switch {
		case field.value == "":
		case !used[field.name]:
			errs.Add(field.name, "is not used by auth_mechanism "+c.AuthMechanism)
		case strings.ContainsFunc(field.value, func(r rune) bool { return r < ' ' || r == 0x7f }):
			errs.Add(field.name, "must not contain control characters")
		}
	}
	switch {
	case isLocalhost(c.Host):
	case c.AuthMechanism == authPlain && c.TLSMode == tlsModeNone:
		errs.Add("auth_mechanism", "plain requires TLS; tls_mode none is accepted only for localhost")
	case c.AuthMechanism == authXOAuth2 && (c.TLSMode == tlsModeNone || c.TLSMode == tlsModeOpportunistic):
		errs.Add("auth_mechanism", "xoauth2 requires tls_mode starttls or implicit, except for localhost")
	}
	return errs
}

func requireField(errs *utils.ValidationErrors, field, value, mechanism string) {
	if value == "" {
		errs.Add(field, "is required with auth_mechanism "+mechanism)
	}
}

func (c *config) validateAddresses() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.From == "" {
		errs.Add("from", "is required")
	} else if _, err := netmail.ParseAddress(c.From); err != nil {
		errs.Add("from", "must be one RFC 5322 address")
	}
	if len(c.To) == 0 {
		errs.Add("to", "is required")
	}
	for i, to := range c.To {
		if _, err := netmail.ParseAddress(to); err != nil {
			errs.Add(fmt.Sprintf("to[%d]", i), "must be one RFC 5322 address")
		}
	}
	return errs
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}

	tlsConfig, err := shared.BuildTLSConfig(&cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("%s tls: %w", name, err)
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = cfg.Host
	}

	// The driver dials implicit TLS itself, so go-mail must not attempt STARTTLS on it.
	policy := map[string]mail.TLSPolicy{
		tlsModeStartTLS: mail.TLSMandatory, tlsModeOpportunistic: mail.TLSOpportunistic,
		tlsModeImplicit: mail.NoTLS, tlsModeNone: mail.NoTLS,
	}[cfg.TLSMode]

	d := &driver{
		cfg:       cfg,
		tlsConfig: tlsConfig,
		options: append([]mail.Option{
			mail.WithPort(cfg.Port),
			mail.WithTLSPolicy(policy),
			mail.WithTLSConfig(tlsConfig),
			mail.WithoutNoop(),
		}, authOptions(&cfg)...),
	}
	d.from, _ = netmail.ParseAddress(cfg.From)
	for _, to := range cfg.To {
		addr, _ := netmail.ParseAddress(to)
		d.to = append(d.to, addr)
	}
	return d, nil
}

func (d *driver) Name() string { return name }

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (d *driver) Init(context.Context) error { return nil }

// Close is a no-op: every session closes its own connection.
func (d *driver) Close() error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	msg, err := d.message(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpRenderMessage, err)
	}
	client, conn, end, err := d.session(ctx)
	if err != nil {
		return err
	}
	defer end()
	if err := client.SendWithSMTPClient(conn, msg); err != nil {
		diagnostic := newDeliveryError(ctx, shared.OpSend, err)
		// go-mail keeps only the last RCPT reply: with several recipients a 5yz there does not show
		// that every recipient was refused, so the delivery stays retriable.
		if diagnostic.Operation == opRcpt && len(d.cfg.To) > 1 {
			diagnostic.Permanent = false
		}
		return diagnostic
	}
	// The server accepted the message; a failed QUIT does not undo that.
	_ = client.CloseWithSMTPClient(conn)
	return nil
}

// HealthCheck runs a session up to authentication and quits without sending mail.
func (d *driver) HealthCheck(ctx context.Context) error {
	client, conn, end, err := d.session(ctx)
	if err != nil {
		return markMisconfigured(err)
	}
	defer end()
	if err := client.CloseWithSMTPClient(conn); err != nil {
		return markMisconfigured(newDeliveryError(ctx, opQuit, err))
	}
	return nil
}

// session aborts the connection when ctx ends: go-mail observes ctx only while dialing.
func (d *driver) session(ctx context.Context) (client *mail.Client, conn *gosmtp.Client, end func(), err error) {
	timeout := sessionTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, nil, nil, shared.WrapDeliveryError(name, shared.OpConnect, context.DeadlineExceeded)
	}

	var (
		raw  net.Conn
		stop = func() bool { return false }
	)
	// go-mail joins host and port with a colon, which breaks an IPv6 literal; the driver joins them itself.
	address := net.JoinHostPort(d.cfg.Host, strconv.Itoa(d.cfg.Port))
	dial := func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		dialer := &net.Dialer{}
		var err error
		if d.cfg.TLSMode == tlsModeImplicit {
			raw, err = (&tls.Dialer{NetDialer: dialer, Config: d.tlsConfig}).DialContext(dialCtx, network, address)
		} else {
			raw, err = dialer.DialContext(dialCtx, network, address)
		}
		if err != nil {
			return nil, err
		}
		conn := raw
		stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
		return raw, nil
	}

	options := append(append([]mail.Option(nil), d.options...), mail.WithTimeout(timeout), mail.WithDialContextFunc(dial))
	client, err = mail.NewClient(d.cfg.Host, options...)
	if err != nil {
		return nil, nil, nil, shared.WrapDeliveryError(name, shared.OpConnect, err)
	}
	end = func() {
		stop()
		if raw != nil {
			_ = raw.Close()
		}
	}
	conn, err = client.DialToSMTPClientWithContext(ctx)
	if err != nil {
		end()
		return nil, nil, nil, newDeliveryError(ctx, shared.OpConnect, err)
	}
	return client, conn, end, nil
}

// newDeliveryError reports an SMTP failure by stage and reply code; reply text can echo submitted values.
// A 5yz reply is a permanent negative completion (RFC 5321 section 4.2.1).
func newDeliveryError(ctx context.Context, operation string, err error) *shared.DeliveryError {
	if ctxErr := contextError(ctx); ctxErr != nil {
		return shared.NewDeliveryError(name, operation, ctxErr)
	}
	if sendErr, ok := errors.AsType[*mail.SendError](err); ok {
		operation = sendStage(sendErr.Reason)
	}
	if code := replyCode(err); code != 0 {
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: operation,
			Code: fmt.Sprintf("server replied %d", code), Permanent: code >= 500 && code < 600,
		}
	}
	if code := capabilityFailure(err); code != "" {
		return &shared.DeliveryError{Cause: err, Output: name, Operation: operation, Code: code, Permanent: true}
	}
	return shared.NewDeliveryError(name, operation, err)
}

func sendStage(reason mail.SendErrReason) string {
	switch reason {
	case mail.ErrSMTPMailFrom:
		return opMail
	case mail.ErrSMTPRcptTo:
		return opRcpt
	case mail.ErrSMTPData, mail.ErrSMTPDataClose, mail.ErrWriteContent:
		return opData
	default:
		return shared.OpSend
	}
}

// replyCode returns the server reply code carried by err, or 0.
func replyCode(err error) int {
	if sendErr, ok := errors.AsType[*mail.SendError](err); ok && sendErr.ErrorCode() != 0 {
		return sendErr.ErrorCode()
	}
	if reply, ok := errors.AsType[*textproto.Error](err); ok {
		return reply.Code
	}
	return 0
}

// contextError reports why ctx ended: the connection deadline equals it and can fire first.
func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// capabilityFailure names a server or mechanism mismatch; go-mail reports a missing STARTTLS or AUTH
// extension only as text, so those two are matched on its fixed messages.
func capabilityFailure(err error) string {
	message := err.Error()
	switch {
	case errors.Is(err, gosmtp.ErrUnencrypted):
		return codeUnencrypted
	case errors.Is(err, mail.ErrPlainAuthNotSupported), errors.Is(err, mail.ErrXOauth2AuthNotSupported):
		return codeNoMechanism
	case strings.Contains(message, "does not support STARTTLS"):
		return codeNoStartTLS
	case strings.Contains(message, "does not support SMTP AUTH"):
		return codeNoAuth
	default:
		return ""
	}
}

// misconfiguredReplies are permanent STARTTLS or AUTH replies: RFC 4954 section 6, RFC 3207 section 4, RFC 5321.
var misconfiguredReplies = map[int]bool{
	504: true, // mechanism or command parameter not implemented
	530: true, // authentication required
	534: true, // mechanism too weak
	535: true, // credentials invalid
	538: true, // encryption required for mechanism
}

// markMisconfigured flags a probe failure that no configuration-preserving retry can fix.
func markMisconfigured(err error) error {
	diagnostic, ok := errors.AsType[*shared.DeliveryError](err)
	if !ok {
		return err
	}
	if diagnostic.Cause != nil && (misconfiguredReplies[replyCode(diagnostic.Cause)] ||
		capabilityFailure(diagnostic.Cause) != "" || shared.IsTLSVerificationError(diagnostic.Cause)) {
		marked := *diagnostic
		marked.Misconfigured = true
		return &marked
	}
	return err
}

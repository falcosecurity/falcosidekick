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
)

var (
	errNoStartTLS  = errors.New("server does not offer STARTTLS")
	errNoAuth      = errors.New("server does not offer AUTH")
	errNoMechanism = errors.New("server does not offer the auth mechanism")
	errUnencrypted = errors.New("authentication requires TLS")
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
	switch {
	case c.Host == "":
		errs.Add("host", "is required")
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
		errs.Add("tls_mode", fmt.Sprintf("must be starttls/implicit/opportunistic/none, got %q", c.TLSMode))
	}
	if c.Port < 1 || c.Port > 65535 {
		errs.Add("port", "must be between 1 and 65535")
	}
	errs.Merge("", c.validateAuth())
	errs.Merge("", c.validateAddresses())
	if c.OutputFormat == "" {
		c.OutputFormat = formatHTML
	} else if c.OutputFormat != formatHTML && c.OutputFormat != formatText {
		errs.Add("output_format", fmt.Sprintf("must be html/text, got %q", c.OutputFormat))
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
		errs.Add("auth_mechanism", fmt.Sprintf("must be plain/xoauth2/none, got %q", c.AuthMechanism))
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
		return nil, fmt.Errorf("smtp config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("smtp: %s", errs.Error())
	}

	tlsConfig, err := shared.BuildTLSConfig(&cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("smtp tls: %w", err)
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = cfg.Host
	}

	// Implicit TLS is dialed by the driver, so go-mail sees an encrypted
	// connection and must not attempt STARTTLS on it.
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

// Send delivers the event as one email in its own SMTP session.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	msg, err := d.message(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, "render message", err)
	}
	client, conn, end, err := d.session(ctx)
	if err != nil {
		return err
	}
	defer end()
	if err := client.SendWithSMTPClient(conn, msg); err != nil {
		return sendError(ctx, err)
	}
	// The server accepted the message; a failed QUIT does not undo that.
	_ = client.CloseWithSMTPClient(conn)
	return nil
}

// HealthCheck runs a session up to authentication and quits without
// sending mail. Rejected credentials or TLS setup are misconfigurations.
func (d *driver) HealthCheck(ctx context.Context) error {
	client, conn, end, err := d.session(ctx)
	if err != nil {
		return classify(err)
	}
	defer end()
	if err := client.CloseWithSMTPClient(conn); err != nil {
		return classify(stageError(ctx, "quit", err))
	}
	return nil
}

// session connects, negotiates TLS and authenticates. go-mail observes ctx
// only while dialing, so the driver dials and aborts the connection when
// ctx ends. The returned function releases the connection.
func (d *driver) session(ctx context.Context) (client *mail.Client, conn *gosmtp.Client, end func(), err error) {
	timeout := sessionTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, nil, nil, shared.WrapDeliveryError(name, "connect", context.DeadlineExceeded)
	}

	var (
		raw  net.Conn
		stop = func() bool { return false }
	)
	dial := func(dialCtx context.Context, network, address string) (net.Conn, error) {
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
		return nil, nil, nil, shared.WrapDeliveryError(name, "connect", err)
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
		return nil, nil, nil, stageError(ctx, "connect", err)
	}
	return client, conn, end, nil
}

// replyError reports an SMTP reply code without the server text, which can
// echo submitted values.
type replyError struct {
	cause error
	stage string
	code  int
}

func (e *replyError) Error() string {
	return fmt.Sprintf("smtp %s: server replied %d", e.stage, e.code)
}

func (e *replyError) Unwrap() error { return e.cause }

// stageError turns a session failure into an error that names the stage
// and never carries server text or credentials.
func stageError(ctx context.Context, stage string, err error) error {
	if ctxErr := contextError(ctx); ctxErr != nil {
		return shared.WrapDeliveryError(name, stage, ctxErr)
	}
	if reply, ok := errors.AsType[*textproto.Error](err); ok {
		return &replyError{stage: stage, code: reply.Code, cause: err}
	}
	if known := knownError(err); known != nil {
		return fmt.Errorf("smtp %s: %w", stage, known)
	}
	return shared.WrapDeliveryError(name, stage, err)
}

// contextError reports why ctx ended. The session timeout equals the
// context deadline, so a connection deadline can fire just before ctx
// reports it.
func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// knownError maps go-mail failures that a retry cannot fix to fixed texts.
// go-mail reports a missing STARTTLS or AUTH extension only as text.
func knownError(err error) error {
	message := err.Error()
	switch {
	case errors.Is(err, gosmtp.ErrUnencrypted):
		return errUnencrypted
	case errors.Is(err, mail.ErrPlainAuthNotSupported), errors.Is(err, mail.ErrXOauth2AuthNotSupported):
		return errNoMechanism
	case strings.Contains(message, "does not support STARTTLS"):
		return errNoStartTLS
	case strings.Contains(message, "does not support SMTP AUTH"):
		return errNoAuth
	}
	return nil
}

// sendError reports a failed delivery by its SMTP stage and reply code.
func sendError(ctx context.Context, err error) error {
	if ctxErr := contextError(ctx); ctxErr != nil {
		return shared.WrapDeliveryError(name, "send", ctxErr)
	}
	sendErr, ok := errors.AsType[*mail.SendError](err)
	if !ok {
		return shared.WrapDeliveryError(name, "send", err)
	}
	stage := "send"
	switch sendErr.Reason {
	case mail.ErrSMTPMailFrom:
		stage = "mail"
	case mail.ErrSMTPRcptTo:
		stage = "rcpt"
	case mail.ErrSMTPData, mail.ErrSMTPDataClose, mail.ErrWriteContent:
		stage = "data"
	default:
	}
	if code := sendErr.ErrorCode(); code != 0 {
		return &replyError{stage: stage, code: code, cause: err}
	}
	return shared.WrapDeliveryError(name, stage, err)
}

// misconfiguredReplies are permanent replies to STARTTLS or AUTH that a
// retry cannot fix (RFC 4954 section 6, RFC 3207 section 4, RFC 5321).
var misconfiguredReplies = map[int]bool{
	504: true, // mechanism or command parameter not implemented
	530: true, // authentication required
	534: true, // mechanism too weak
	535: true, // credentials invalid
	538: true, // encryption required for mechanism
}

func classify(err error) error {
	if reply, ok := errors.AsType[*replyError](err); ok && misconfiguredReplies[reply.code] {
		return fmt.Errorf("%w: %w", output.ErrMisconfigured, err)
	}
	for _, permanent := range []error{errUnencrypted, errNoMechanism, errNoStartTLS, errNoAuth} {
		if errors.Is(err, permanent) {
			return fmt.Errorf("%w: %w", output.ErrMisconfigured, err)
		}
	}
	return shared.ClassifyMisconfiguration(err)
}

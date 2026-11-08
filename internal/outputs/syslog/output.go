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

package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "syslog"

	protocolUDP = "udp"
	protocolTCP = "tcp"
	protocolTLS = "tls"

	formatJSON = "json"
	formatCEF  = "cef"

	defaultPort     = 514
	defaultTLSPort  = 6514
	defaultFacility = "local0"

	// ioTimeout bounds a dial or write when the context has no deadline.
	ioTimeout = 10 * time.Second
	// probeTimeout bounds the read that detects a receiver closing a stream connection.
	probeTimeout = time.Millisecond
)

var errClosed = errors.New("output closed")

type config struct {
	TLS      shared.TLSClientConfig `mapstructure:"tls"`
	Host     string                 `mapstructure:"host"`
	Protocol string                 `mapstructure:"protocol"`
	Format   string                 `mapstructure:"format"`
	Facility string                 `mapstructure:"facility"`
	Runtime  output.RuntimeConfig   `mapstructure:"runtime"`
	Port     int                    `mapstructure:"port"`
}

// OutputType describes the Syslog output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryLogs,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "host", Type: "string", Required: true, Label: "Host"},
			{Name: "port", Type: "int", Label: "Port (514, or 6514 with tls)"},
			{Name: "protocol", Type: "enum", Values: []string{protocolTCP, protocolUDP, protocolTLS}, Default: protocolTCP, Label: "Protocol"},
			{Name: "format", Type: "enum", Values: []string{formatJSON, formatCEF}, Default: formatJSON, Label: "Message Format"},
			{Name: "facility", Type: "enum", Values: shared.SortMapKeys(facilities), Default: defaultFacility, Label: "Facility"},
		}, append(shared.TLSClientSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

// driver keeps one connection, owned by whoever holds sem.
type driver struct {
	dial          func(ctx context.Context) (net.Conn, error)
	conn          net.Conn
	logger        *slog.Logger
	sem           chan struct{}
	localHostname string
	cfg           config
	facility      int
	closed        bool
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	switch {
	case c.Host == "":
		errs.Add("host", "is required")
	case strings.ContainsAny(c.Host, "/?#@ \t\r\n"):
		errs.Add("host", "must be a host name or IP address without scheme, port or path")
	}
	if c.Protocol == "" {
		c.Protocol = protocolTCP
	}
	switch c.Protocol {
	case protocolTCP, protocolUDP, protocolTLS:
	default:
		errs.Add("protocol", "must be tcp/udp/tls")
	}
	if c.Port == 0 {
		c.Port = defaultPort
		if c.Protocol == protocolTLS {
			c.Port = defaultTLSPort
		}
	} else if c.Port < 1 || c.Port > 65535 {
		errs.Add("port", "must be between 1 and 65535")
	}
	if c.Format == "" {
		c.Format = formatJSON
	} else if c.Format != formatJSON && c.Format != formatCEF {
		errs.Add("format", "must be json/cef")
	}
	if c.Facility == "" {
		c.Facility = defaultFacility
	} else if _, ok := facilities[c.Facility]; !ok {
		errs.Add("facility", "must be one of "+strings.Join(shared.SortMapKeys(facilities), "/"))
	}
	if c.Protocol != protocolTLS && c.TLS != (shared.TLSClientConfig{}) {
		errs.Add("tls", "requires protocol tls")
	}
	errs.Merge("tls", c.TLS.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}

	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := &driver{
		cfg:           cfg,
		facility:      facilities[cfg.Facility],
		logger:        shared.ResolveLogger(deps.Logger, name),
		sem:           make(chan struct{}, 1),
		localHostname: nilValue,
	}
	if hostname, err := os.Hostname(); err == nil && validHostname(hostname) {
		d.localHostname = hostname
	}

	netDialer := &net.Dialer{Timeout: ioTimeout}
	switch cfg.Protocol {
	case protocolTLS:
		tlsCfg, err := shared.BuildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("%s tls: %w", name, err)
		}
		tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: tlsCfg}
		d.dial = func(ctx context.Context) (net.Conn, error) { return tlsDialer.DialContext(ctx, "tcp", address) }
	default:
		network := cfg.Protocol
		d.dial = func(ctx context.Context) (net.Conn, error) { return netDialer.DialContext(ctx, network, address) }
	}
	return d, nil
}

func (d *driver) Name() string { return name }

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

// Init connects lazily: the first Send or HealthCheck dials.
func (d *driver) Init(context.Context) error { return nil }

// Send writes one message, dialing again when the connection is gone.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	msg, err := d.message(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}
	if err := d.acquire(ctx); err != nil {
		return shared.WrapDeliveryError(name, shared.OpWrite, err)
	}
	defer d.release()

	conn, err := d.connection(ctx)
	if err != nil {
		return err
	}
	if err := write(ctx, conn, msg); err != nil {
		d.drop()
		return shared.WrapDeliveryError(name, shared.OpWrite, err)
	}
	return nil
}

// HealthCheck dials stream receivers and keeps the connection; UDP has no handshake to probe.
func (d *driver) HealthCheck(ctx context.Context) error {
	if d.cfg.Protocol == protocolUDP {
		return nil
	}
	if err := d.acquire(ctx); err != nil {
		return shared.WrapDeliveryError(name, shared.OpDial, err)
	}
	defer d.release()
	if _, err := d.connection(ctx); err != nil {
		return shared.ClassifyMisconfiguration(err)
	}
	return nil
}

// Close waits for the write in progress, which its deadline bounds.
func (d *driver) Close() error {
	d.sem <- struct{}{}
	defer d.release()
	d.closed = true
	if d.conn == nil {
		return nil
	}
	err := d.conn.Close()
	d.conn = nil
	return err
}

func (d *driver) acquire(ctx context.Context) error {
	select {
	case d.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *driver) release() { <-d.sem }

// connection replaces a connection the receiver closed; the caller holds sem.
func (d *driver) connection(ctx context.Context) (net.Conn, error) {
	if d.closed {
		return nil, shared.WrapDeliveryError(name, shared.OpDial, errClosed)
	}
	if d.conn != nil && d.cfg.Protocol != protocolUDP && peerClosed(d.conn) {
		d.logger.Debug("receiver closed the connection, reconnecting")
		d.drop()
	}
	if d.conn != nil {
		return d.conn, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, ioTimeout)
	defer cancel()
	conn, err := d.dial(dialCtx)
	if err != nil {
		return nil, shared.WrapDeliveryError(name, shared.OpDial, err)
	}
	d.conn = conn
	return conn, nil
}

func (d *driver) drop() {
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}

// peerClosed treats any read result but a timeout as closed: receivers never write.
func peerClosed(conn net.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		return true
	}
	var buf [1]byte
	_, err := conn.Read(buf[:])
	if err == nil {
		return true
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return conn.SetReadDeadline(time.Time{}) != nil
	}
	return true
}

// write uses the context deadline, or ioTimeout without one, and stops as soon as ctx ends.
func write(ctx context.Context, conn net.Conn, msg []byte) error {
	deadline := time.Now().Add(ioTimeout)
	ctxDeadline := false
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline, ctxDeadline = d, true
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(msg); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() && ctxDeadline {
			<-ctx.Done()
			return ctx.Err()
		}
		return err
	}
	return nil
}

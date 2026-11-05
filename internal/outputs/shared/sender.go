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

package shared

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

const (
	userAgent         = "falcosidekick/v3"
	maxErrorBodyBytes = 4096
)

// Sender handles HTTP request execution and response checking for output drivers.
type Sender struct {
	client    *http.Client
	headers   map[string]ValueSources
	basicUser string
	basicPass string
	name      string
}

// NewSender creates a Sender with a pre-configured HTTP client.
// Auth from HTTPConfig (basic auth, bearer token) is auto-configured.
// Returns an error if headers, authentication, or TLS configuration is invalid.
// Header value files are checked even if the driver has already validated its config.
func NewSender(name string, cfg *HTTPConfig) (*Sender, error) {
	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	client, err := BuildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	headers := make(map[string]ValueSources, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[http.CanonicalHeaderKey(k)] = ValueSources{
			Values: slices.Clone(v.Values), Secrets: slices.Clone(v.Secrets), Files: slices.Clone(v.Files),
		}
	}

	s := &Sender{
		name:    name,
		client:  client,
		headers: headers,
	}

	if cfg.Username != "" {
		s.basicUser = cfg.Username
		s.basicPass = cfg.Password
	}
	if cfg.BearerToken != "" {
		s.SetHeader("Authorization", "Bearer "+cfg.BearerToken)
	}

	return s, nil
}

// SetBasicAuth configures basic authentication before the sender is used.
func (s *Sender) SetBasicAuth(user, pass string) {
	s.basicUser = user
	s.basicPass = pass
}

// SetHeader replaces a configured header before the sender is used.
func (s *Sender) SetHeader(key, value string) {
	s.headers[http.CanonicalHeaderKey(key)] = ValueSources{Secrets: []string{value}}
}

// SendJSON marshals payload as JSON and sends with the given HTTP method.
func (s *Sender) SendJSON(ctx context.Context, method, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return WrapDeliveryError(s.name, "marshal", err)
	}
	return s.SendRaw(ctx, method, url, body, "application/json")
}

// SendGzipJSON marshals payload as JSON, gzip-compresses it, and sends with Content-Encoding: gzip.
func (s *Sender) SendGzipJSON(ctx context.Context, method, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return WrapDeliveryError(s.name, "marshal", err)
	}
	return s.SendGzipRaw(ctx, method, url, body, "application/json")
}

// SendRaw sends pre-built bytes with the given content type and HTTP method.
func (s *Sender) SendRaw(ctx context.Context, method, url string, body []byte, contentType string) error {
	req, err := s.buildRequest(ctx, method, url, body, contentType)
	if err != nil {
		return err
	}
	return s.Do(ctx, req)
}

// SendGzipRaw gzip-compresses raw bytes and sends with Content-Encoding: gzip.
func (s *Sender) SendGzipRaw(ctx context.Context, method, url string, body []byte, contentType string) error {
	compressed, err := gzipCompress(body)
	if err != nil {
		return WrapDeliveryError(s.name, "gzip", err)
	}
	req, err := s.buildRequest(ctx, method, url, compressed, contentType)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "gzip")
	return s.Do(ctx, req)
}

// SendJSONCheckBody marshals, sends, and validates the response body.
// Non-2xx responses always fail; a bounded body check may add a safe DeliveryError code.
func (s *Sender) SendJSONCheckBody(ctx context.Context, method, url string, payload any, check func(body []byte) error) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return WrapDeliveryError(s.name, "marshal", err)
	}
	req, err := s.buildRequest(ctx, method, url, body, "application/json")
	if err != nil {
		return err
	}
	_, err = s.readBody(req, check)
	return err
}

// SendRawReadBody sends bytes and returns the response body on success.
// For APIs where the response body contains per-item results (ES bulk).
func (s *Sender) SendRawReadBody(ctx context.Context, method, url string, body []byte, contentType string) ([]byte, error) {
	req, err := s.buildRequest(ctx, method, url, body, contentType)
	if err != nil {
		return nil, err
	}
	return s.DoReadBody(ctx, req)
}

// HealthCheck sends GET url. Rejected credentials (401, 403), a missing path
// (404) and an untrusted certificate wrap output.ErrMisconfigured, except
// the statuses listed in transient; other failures are returned as they
// are, since they may pass once the destination is up.
func (s *Sender) HealthCheck(ctx context.Context, url string, transient ...int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return WrapDeliveryError(s.name, "healthcheck", err)
	}
	err = s.Do(ctx, req)
	if isMisconfiguration(err, transient) {
		return fmt.Errorf("%w: %w", output.ErrMisconfigured, err)
	}
	return err
}

func isMisconfiguration(err error, transient []int) bool {
	switch status := HTTPStatus(err); status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return !slices.Contains(transient, status)
	}
	return IsTLSVerificationError(err)
}

// Do executes a prepared request. Only 2xx is success.
func (s *Sender) Do(ctx context.Context, req *http.Request) error {
	resp, err := s.execute(req)
	if err != nil {
		return err
	}
	defer drain(resp)

	if resp.StatusCode/100 != 2 {
		return &DeliveryError{name: s.name, operation: "response", status: resp.StatusCode}
	}
	return nil
}

// DoReadBody executes a request and returns the full response body on 2xx.
func (s *Sender) DoReadBody(ctx context.Context, req *http.Request) ([]byte, error) {
	return s.readBody(req, nil)
}

func (s *Sender) readBody(req *http.Request, check func([]byte) error) ([]byte, error) {
	resp, err := s.execute(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return nil, s.responseError(resp, check)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, WrapDeliveryError(s.name, "read response", err)
	}
	if check != nil {
		if err := check(body); err != nil {
			return nil, WrapDeliveryError(s.name, "response", err)
		}
	}
	return body, nil
}

func (s *Sender) responseError(resp *http.Response, check func([]byte) error) error {
	diagnostic := &DeliveryError{name: s.name, operation: "response", status: resp.StatusCode}
	if check == nil {
		return diagnostic
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes+1))
	if err != nil {
		diagnostic.cause = err
		return diagnostic
	}
	if len(body) > maxErrorBodyBytes {
		return diagnostic
	}
	diagnostic.cause = check(body)
	var protocol *DeliveryError
	if errors.As(diagnostic.cause, &protocol) && protocol != nil {
		diagnostic.reason = protocol.reason
	}
	return diagnostic
}

// execute applies headers, auth, and runs the HTTP request.
func (s *Sender) execute(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", userAgent)
	if err := ApplyHeaders(req, s.headers); err != nil {
		return nil, &DeliveryError{name: s.name, operation: "headers", reason: err.Error(), cause: err}
	}
	if s.basicUser != "" {
		req.SetBasicAuth(s.basicUser, s.basicPass)
	}

	resp, err := s.client.Do(req) //nolint:gosec // output URLs are user-configured
	if err != nil {
		return nil, WrapDeliveryError(s.name, "send", err)
	}
	return resp, nil
}

// buildRequest creates an HTTP request with content type set.
func (s *Sender) buildRequest(ctx context.Context, method, url string, body []byte, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, WrapDeliveryError(s.name, "request", err)
	}
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drain reads the response body to EOF and closes it.
// Reading to EOF enables HTTP/1.1 keep-alive connection reuse.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

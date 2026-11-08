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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeliveryErrorClassification(t *testing.T) {
	tests := []struct {
		cause     error
		name      string
		operation string
		want      string
	}{
		{context.Canceled, "canceled", "send", "request canceled"},
		{context.DeadlineExceeded, "deadline", "send", "timeout (deadline exceeded)"},
		{&net.DNSError{Name: "private-token", IsTimeout: true}, "network timeout", "send", "timeout"},
		{&net.DNSError{Name: "private-token", Err: "private-token"}, "DNS", "send", "DNS resolution failed"},
		{&tls.CertificateVerificationError{Err: errors.New("private-token")}, "certificate verification", "send", "TLS certificate verification failed"},
		{x509.UnknownAuthorityError{}, "unknown authority", "send", "TLS certificate verification failed"},
		{x509.HostnameError{Host: "private-token"}, "certificate hostname", "send", "TLS certificate verification failed"},
		{x509.CertificateInvalidError{}, "invalid certificate", "send", "TLS certificate verification failed"},
		{tls.RecordHeaderError{Msg: "private-token"}, "invalid TLS", "send", "invalid TLS response"},
		{syscall.ECONNREFUSED, "connection refused", "send", "connection refused"},
		{syscall.ECONNRESET, "connection reset", "send", "connection closed"},
		{syscall.EPIPE, "broken pipe", "send", "connection closed"},
		{io.EOF, "EOF", "read response", "connection closed"},
		{io.ErrUnexpectedEOF, "truncated response", "read response", "incomplete response"},
		{&json.SyntaxError{}, "JSON syntax", "response", "invalid JSON"},
		{&json.UnmarshalTypeError{Value: "private-token", Field: "private-token", Type: reflect.TypeFor[int]()}, "JSON type", "response", "unexpected JSON type"},
		{errors.New("private-token"), "marshal", "marshal", "cannot encode payload"},
		{errors.New("private-token"), "request", "request", "invalid request"},
		{errors.New("private-token"), "healthcheck", "healthcheck", "invalid request"},
		{errors.New("private-token"), "read", "read response", "cannot read response"},
		{errors.New("private-token"), "response", "response", "unexpected response"},
		{errors.New("private-token"), "compression", "gzip", "cannot compress payload"},
		{errors.New("private-token"), "template", "render message", "cannot render message template"},
		{errors.New("private-token"), "unknown send failure", "send", "request failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := &url.Error{Op: "Post", URL: "https://private-token.example/path/private-token?key=private-token", Err: tt.cause}
			err := WrapDeliveryError("webhook", tt.operation, cause)
			require.Error(t, err)
			assert.Equal(t, "webhook "+tt.operation+": "+tt.want, err.Error())
			assert.ErrorIs(t, err, tt.cause)
			var original *url.Error
			require.ErrorAs(t, err, &original)
			assert.Same(t, cause, original)
			assertSafeDeliveryFormatting(t, err)
		})
	}
	assert.NoError(t, WrapDeliveryError("webhook", "send", nil))
}

func TestDeliveryErrorPreservesSafeDiagnosticNotUnsafeWrapper(t *testing.T) {
	safe := NewProtocolError("slack", "invalid_token")
	cause := fmt.Errorf("private-token: %w", safe)
	err := WrapDeliveryError("slack", "response", cause)
	assert.Equal(t, "slack response: invalid_token", err.Error())
	assert.ErrorIs(t, err, safe)
	assert.ErrorIs(t, err, cause)
	assertSafeDeliveryFormatting(t, err)
}

func TestSenderRuntimeErrorsDoNotExposeCredentials(t *testing.T) {
	for _, readBody := range []bool{false, true} {
		t.Run(fmt.Sprintf("read_body_%t", readBody), func(t *testing.T) {
			s, err := NewSender("webhook", &HTTPConfig{})
			require.NoError(t, err)
			cause := context.DeadlineExceeded
			s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) { return nil, cause })
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://collector.example/private-token?token=private-token", http.NoBody)
			require.NoError(t, err)
			if readBody {
				body, sendErr := s.DoReadBody(context.Background(), req)
				err = sendErr
				assert.Nil(t, body)
			} else {
				err = s.Do(context.Background(), req)
			}
			require.Error(t, err)
			assert.Equal(t, "webhook send: timeout (deadline exceeded)", err.Error())
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			var timeout net.Error
			require.ErrorAs(t, err, &timeout)
			assert.True(t, timeout.Timeout())
			assertSafeDeliveryFormatting(t, err)
		})
	}
}

func TestSenderResponseErrorsDoNotExposeBody(t *testing.T) {
	for _, readBody := range []bool{false, true} {
		t.Run(fmt.Sprintf("read_body_%t", readBody), func(t *testing.T) {
			s, err := NewSender("webhook", &HTTPConfig{})
			require.NoError(t, err)
			body := &diagnosticResponseBody{Reader: bytes.NewBufferString("private-token")}
			s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusUnauthorized, Status: "private-token", Body: body}, nil
			})
			if readBody {
				response, sendErr := s.SendRawReadBody(context.Background(), http.MethodPost, "https://collector.example", nil, "application/json")
				err = sendErr
				assert.Nil(t, response)
			} else {
				err = s.SendRaw(context.Background(), http.MethodPost, "https://collector.example", nil, "application/json")
			}
			require.EqualError(t, err, "webhook response: HTTP 401 Unauthorized")
			assert.True(t, body.closed)
			assertSafeDeliveryFormatting(t, err)
		})
	}
}

func TestSenderReadAndCallbackErrorsKeepSafeCauses(t *testing.T) {
	s, err := NewSender("webhook", &HTTPConfig{})
	require.NoError(t, err)
	cause := errors.New("private-token")
	body := &diagnosticResponseBody{readErr: cause}
	s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	response, err := s.SendRawReadBody(context.Background(), http.MethodPost, "https://collector.example", nil, "application/json")
	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "cannot read response")
	assert.True(t, body.closed)
	assertSafeDeliveryFormatting(t, err)

	s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("private-token"))}, nil
	})
	err = s.SendJSONCheckBody(context.Background(), http.MethodPost, "https://collector.example", nil, func(response []byte) error {
		assert.Equal(t, "private-token", string(response))
		return cause
	})
	assert.EqualError(t, err, "webhook response: unexpected response")
	assert.ErrorIs(t, err, cause)
	assertSafeDeliveryFormatting(t, err)
}

func TestSenderBuildErrorsDoNotExposeCredentials(t *testing.T) {
	s, err := NewSender("webhook", &HTTPConfig{})
	require.NoError(t, err)
	for _, send := range []struct {
		call func() error
		name string
	}{
		{name: "request", call: func() error {
			return s.SendRaw(context.Background(), http.MethodPost, "https://collector.example/private-token%zz", nil, "application/json")
		}},
		{name: "healthcheck", call: func() error { return s.HealthCheck(context.Background(), "https://collector.example/private-token%zz") }},
		{name: "marshal", call: func() error {
			return s.SendJSON(context.Background(), http.MethodPost, "https://collector.example", diagnosticPayload{})
		}},
		{name: "gzip marshal", call: func() error {
			return s.SendGzipJSON(context.Background(), http.MethodPost, "https://collector.example", diagnosticPayload{})
		}},
		{name: "callback marshal", call: func() error {
			return s.SendJSONCheckBody(context.Background(), http.MethodPost, "https://collector.example", diagnosticPayload{}, func([]byte) error { t.Fatal("callback must not run"); return nil })
		}},
	} {
		t.Run(send.name, func(t *testing.T) {
			err := send.call()
			require.Error(t, err)
			assertSafeDeliveryFormatting(t, err)
		})
	}
}

func TestSenderRedirectFailureDiagnostics(t *testing.T) {
	for _, malformed := range []bool{true, false} {
		t.Run(fmt.Sprintf("malformed_location_%t", malformed), func(t *testing.T) {
			s, err := NewSender("webhook", &HTTPConfig{})
			require.NoError(t, err)
			body := &diagnosticResponseBody{Reader: bytes.NewBufferString("private-token")}
			calls := 0
			s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				location := "/private-token"
				if malformed {
					location += "%zz"
				}
				return &http.Response{
					StatusCode: http.StatusTemporaryRedirect, Body: body,
					Header: http.Header{"Location": {location}},
				}, nil
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://collector.example/private-token", bytes.NewBufferString("event"))
			require.NoError(t, err)
			cause := errors.New("private-token")
			if !malformed {
				req.GetBody = func() (io.ReadCloser, error) { return nil, cause }
			}
			err = s.Do(t.Context(), req)
			require.Error(t, err)
			assert.Equal(t, 1, calls)
			assert.True(t, body.closed)
			if !malformed {
				assert.ErrorIs(t, err, cause)
			}
			assertSafeDeliveryFormatting(t, err)
		})
	}
}

func TestSenderCheckedHTTPErrorDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		body      string
		name      string
		readError bool
		wantCheck bool
	}{
		{name: "bounded body", body: "private-token", wantCheck: true},
		{name: "oversized body", body: strings.Repeat("a", maxErrorBodyBytes+1) + "private-token"},
		{name: "read failure", readError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSender("webhook", &HTTPConfig{})
			require.NoError(t, err)
			reader := bytes.NewBufferString(tc.body)
			body := &diagnosticResponseBody{Reader: reader}
			cause := errors.New("private-token")
			if tc.readError {
				body.readErr = cause
			}
			s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadRequest, Body: body}, nil
			})
			checked := false
			err = s.SendJSONCheckBody(t.Context(), http.MethodPost, "https://collector.example", nil, func([]byte) error {
				checked = true
				return cause
			})
			require.EqualError(t, err, "webhook response: HTTP 400 Bad Request")
			assert.Equal(t, tc.wantCheck, checked)
			assert.True(t, body.closed)
			assert.LessOrEqual(t, len(tc.body)-reader.Len(), maxErrorBodyBytes+1)
			if tc.readError || tc.wantCheck {
				assert.ErrorIs(t, err, cause)
			}
			assertSafeDeliveryFormatting(t, err)
		})
	}
}

func assertSafeDeliveryFormatting(t *testing.T, err error) {
	t.Helper()
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		assert.NotContains(t, fmt.Sprintf(format, err), "private-token")
	}
	encoded, encodeErr := json.Marshal(err)
	require.NoError(t, encodeErr)
	assert.NotContains(t, string(encoded), "private-token")
	var diagnostic string
	require.NoError(t, json.Unmarshal(encoded, &diagnostic))
	assert.Equal(t, err.Error(), diagnostic)
	for _, jsonLog := range []bool{false, true} {
		var buf bytes.Buffer
		var handler slog.Handler = slog.NewTextHandler(&buf, nil)
		if jsonLog {
			handler = slog.NewJSONHandler(&buf, nil)
		}
		slog.New(handler).Error("delivery failed", "error", err)
		assert.NotContains(t, buf.String(), "private-token")
	}
}

type diagnosticResponseBody struct {
	io.Reader
	readErr error
	closed  bool
}

func (b *diagnosticResponseBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.Reader.Read(p)
}

func (b *diagnosticResponseBody) Close() error {
	b.closed = true
	return nil
}

type diagnosticPayload struct{}

func (diagnosticPayload) MarshalJSON() ([]byte, error) { return nil, errors.New("private-token") }

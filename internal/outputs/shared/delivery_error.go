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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
)

// DeliveryError describes a failed HTTP delivery without formatting its cause.
type DeliveryError struct {
	cause     error
	name      string
	operation string
	reason    string
	status    int
}

func (e *DeliveryError) Error() string {
	if e.status != 0 {
		message := fmt.Sprintf("%s %s: HTTP %d", e.name, e.operation, e.status)
		if statusText := http.StatusText(e.status); statusText != "" {
			message += " " + statusText
		}
		if e.reason != "" {
			message += ": " + e.reason
		}
		return message
	}
	return fmt.Sprintf("%s %s: %s", e.name, e.operation, e.reason)
}

// Unwrap returns the original failure for programmatic inspection.
func (e *DeliveryError) Unwrap() error { return e.cause }

// StatusCode returns the HTTP response status, or 0 when no response was received.
func (e *DeliveryError) StatusCode() int { return e.status }

// HTTPStatus returns the HTTP status carried by err, or 0 when there is none.
func HTTPStatus(err error) int {
	var diagnostic *DeliveryError
	if errors.As(err, &diagnostic) && diagnostic != nil {
		return diagnostic.status
	}
	return 0
}

// Format keeps diagnostic formatting from exposing the wrapped cause.
func (e *DeliveryError) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", e.Error())
		return
	}
	_, _ = io.WriteString(state, e.Error())
}

// MarshalText encodes the safe diagnostic, never the wrapped cause.
func (e *DeliveryError) MarshalText() ([]byte, error) { return []byte(e.Error()), nil }

// WrapDeliveryError classifies a failure without copying its message; name and operation must be fixed labels.
func WrapDeliveryError(name, operation string, cause error) error {
	if cause == nil {
		return nil
	}
	var diagnostic *DeliveryError
	if errors.As(cause, &diagnostic) && diagnostic != nil {
		return &DeliveryError{
			name: diagnostic.name, operation: diagnostic.operation,
			reason: diagnostic.reason, status: diagnostic.status, cause: cause,
		}
	}
	return &DeliveryError{name: name, operation: operation, reason: classifyDeliveryError(cause, operation), cause: cause}
}

// NewProtocolError reports a fixed or allowlisted provider code, never unvalidated response content.
func NewProtocolError(name, code string) error {
	return &DeliveryError{name: name, operation: "response", reason: code}
}

// IsTLSVerificationError reports whether err is a server certificate the client does not trust.
func IsTLSVerificationError(err error) bool {
	var (
		certificate *tls.CertificateVerificationError
		authority   x509.UnknownAuthorityError
		hostname    x509.HostnameError
		invalidCert x509.CertificateInvalidError
	)
	return errors.As(err, &certificate) || errors.As(err, &authority) ||
		errors.As(err, &hostname) || errors.As(err, &invalidCert)
}

func classifyDeliveryError(err error, operation string) string {
	var (
		redirect    *redirectError
		timeout     net.Error
		dns         *net.DNSError
		certificate *tls.CertificateVerificationError
		authority   x509.UnknownAuthorityError
		hostname    x509.HostnameError
		invalidCert x509.CertificateInvalidError
		record      tls.RecordHeaderError
		jsonSyntax  *json.SyntaxError
		jsonType    *json.UnmarshalTypeError
	)
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout (deadline exceeded)"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &redirect):
		return redirect.reason
	case errors.As(err, &dns):
		return "DNS resolution failed"
	case errors.As(err, &certificate), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalidCert):
		return "TLS certificate verification failed"
	case errors.As(err, &record):
		return "invalid TLS response"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.EOF):
		return "connection closed"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "incomplete response"
	case errors.As(err, &jsonSyntax):
		return "invalid JSON"
	case errors.As(err, &jsonType):
		return "unexpected JSON type"
	}
	switch operation {
	case "marshal":
		return "cannot encode payload"
	case "request", "build request", "healthcheck":
		return "invalid request"
	case "read response":
		return "cannot read response"
	case "response":
		return "unexpected response"
	case "gzip":
		return "cannot compress payload"
	case "target":
		return "cannot resolve target"
	case "render message":
		return "cannot render message template"
	default:
		return "request failed"
	}
}

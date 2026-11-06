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

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// Operations shared by outputs; a package-specific operation is a constant of its package.
const (
	OpBuildRequest  = "build request"
	OpClose         = "close"
	OpConnect       = "connect"
	OpDial          = "dial"
	OpGzip          = "gzip"
	OpHeaders       = "headers"
	OpHealthcheck   = "healthcheck"
	OpMarshal       = "marshal"
	OpReadResponse  = "read response"
	OpRenderMessage = "render message"
	OpRequest       = "request"
	OpResponse      = "response"
	OpSend          = "send"
	OpTarget        = "target"
	OpWrite         = "write"
)

// DeliveryError is the error every output returns for a failed delivery or probe.
// Its text holds only fixed labels, a recognized code and an HTTP status, never server text or submitted values.
type DeliveryError struct {
	// Cause is the original failure, reachable through errors.Is and errors.As; it is never formatted.
	// An error that sums up several failures holds only the context error they share, if any:
	// errors.Is would otherwise match output.ErrPermanent on one part while the others can still succeed.
	Cause error
	// Output is the output package's name constant.
	Output string
	// Operation is a shared Op constant or a constant of the output package.
	Operation string
	// Code is a fixed label or a code the client library recognized.
	Code string
	// Status is the HTTP status of the response, 0 without one.
	Status int
	// Permanent is set when the destination's protocol says a retry cannot succeed.
	Permanent bool
	// Misconfigured is set when a probe failure refuses the configuration.
	Misconfigured bool
}

func (e *DeliveryError) Error() string {
	return e.Output + " " + e.Operation + ": " + e.Reason()
}

// Reason renders the HTTP status and the code, without the output and operation.
func (e *DeliveryError) Reason() string {
	var status string
	if e.Status != 0 {
		status = fmt.Sprintf("HTTP %d", e.Status)
		if text := http.StatusText(e.Status); text != "" {
			status += " " + text
		}
	}
	switch {
	case status != "" && e.Code != "":
		return status + ": " + e.Code
	case status != "":
		return status
	case e.Code != "":
		return e.Code
	default:
		return "failed"
	}
}

// Unwrap returns Cause for programmatic inspection.
func (e *DeliveryError) Unwrap() error { return e.Cause }

// Is matches output.ErrPermanent for failures a retry with the same event cannot fix,
// and output.ErrMisconfigured for probe failures that refuse the configuration.
// Status alone decides nothing: the protocol that produced the error sets Permanent,
// since a status such as AWS throttling's 400 can ask for a retry.
func (e *DeliveryError) Is(target error) bool {
	switch target {
	case output.ErrMisconfigured:
		return e.Misconfigured
	case output.ErrPermanent:
		return e.Permanent || e.Misconfigured ||
			IsTLSVerificationError(e.Cause) || e.Operation == OpMarshal || e.Operation == OpRenderMessage
	default:
		return false
	}
}

// Format renders Error for every verb, so formatting never reaches Cause.
func (e *DeliveryError) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", e.Error())
		return
	}
	_, _ = io.WriteString(state, e.Error())
}

// MarshalText encodes Error, never Cause.
func (e *DeliveryError) MarshalText() ([]byte, error) { return []byte(e.Error()), nil }

// retriableClientStatus are 4xx answers that a later attempt can turn into success;
// a 409 conflicts with the target's current state, which can change.
var retriableClientStatus = map[int]bool{
	http.StatusRequestTimeout:  true,
	http.StatusConflict:        true,
	http.StatusTooEarly:        true,
	http.StatusTooManyRequests: true,
}

// IsPermanentHTTPStatus reports whether a plain HTTP API says a retry cannot change the answer:
// 4xx except 408, 409, 425 and 429. Protocols with their own retry rules, such as AWS and OTLP, do not use it.
func IsPermanentHTTPStatus(status int) bool {
	return status >= 400 && status < 500 && !retriableClientStatus[status]
}

// HTTPStatus returns the HTTP status carried by err, or 0 when there is none.
func HTTPStatus(err error) int {
	if diagnostic, ok := errors.AsType[*DeliveryError](err); ok && diagnostic != nil {
		return diagnostic.Status
	}
	return 0
}

// WrapDeliveryError reports a transport failure by its class; output and operation must be constants.
// A cause that already holds a DeliveryError keeps its code, status and flags under the caller's operation.
func WrapDeliveryError(outputName, operation string, cause error) error {
	if cause == nil {
		return nil
	}
	return NewDeliveryError(outputName, operation, cause)
}

// NewDeliveryError is WrapDeliveryError for a non-nil cause, returned as a struct a driver can refine.
func NewDeliveryError(outputName, operation string, cause error) *DeliveryError {
	if diagnostic, ok := errors.AsType[*DeliveryError](cause); ok && diagnostic != nil {
		copied := *diagnostic
		copied.Output, copied.Operation, copied.Cause = outputName, operation, cause
		return &copied
	}
	return &DeliveryError{Output: outputName, Operation: operation, Code: classifyDeliveryError(cause, operation), Cause: cause}
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
	case OpMarshal:
		return "cannot encode payload"
	case OpRequest, OpBuildRequest, OpHealthcheck:
		return "invalid request"
	case OpReadResponse:
		return "cannot read response"
	case OpResponse:
		return "unexpected response"
	case OpGzip:
		return "cannot compress payload"
	case OpTarget:
		return "cannot resolve target"
	case OpRenderMessage:
		return "cannot render message template"
	default:
		return "request failed"
	}
}

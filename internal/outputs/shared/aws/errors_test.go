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

package aws

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"syscall"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// sdkError builds the error chain the SDK returns for an error response.
func sdkError(status int, code, message string) error {
	api := &smithy.GenericAPIError{Code: code, Message: message}
	var err error = api
	if status != 0 {
		err = &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      api,
		}}
	}
	return &smithy.OperationError{ServiceID: "S3", OperationName: "PutObject", Err: err}
}

func TestWrapErrorPermanence(t *testing.T) {
	tests := []struct {
		err       error
		name      string
		status    int
		permanent bool
	}{
		{name: "invalid message contents", status: http.StatusBadRequest, err: &sqstypes.InvalidMessageContents{}, permanent: true},
		{name: "sns invalid parameter", status: http.StatusBadRequest, err: &snstypes.InvalidParameterException{}, permanent: true},
		{name: "sqs throttled", status: http.StatusBadRequest, err: &sqstypes.RequestThrottled{}},
		{name: "sqs kms throttled", status: http.StatusBadRequest, err: &sqstypes.KmsThrottled{}},
		{name: "sns kms throttled", status: http.StatusBadRequest, err: &snstypes.KMSThrottlingException{}},
		{name: "sns throttled", status: http.StatusBadRequest, err: &snstypes.ThrottledException{}},
		{name: "sns concurrent access", status: http.StatusBadRequest, err: &snstypes.ConcurrentAccessException{}},
		{name: "sqs over limit", status: http.StatusForbidden, err: &sqstypes.OverLimit{}},
		{name: "generic throttling", status: http.StatusBadRequest, err: &smithy.GenericAPIError{Code: "ThrottlingException", Fault: smithy.FaultClient}},
		{name: "request timeout", status: http.StatusBadRequest, err: &smithy.GenericAPIError{Code: "RequestTimeout", Fault: smithy.FaultClient}},
		{name: "server fault", status: http.StatusInternalServerError, err: &smithy.GenericAPIError{Code: "InternalError", Fault: smithy.FaultServer}},
		{name: "unknown fault", status: http.StatusBadRequest, err: &smithy.GenericAPIError{Code: "Whatever"}},
		{name: "connection refused", err: fmt.Errorf("send: %w", syscall.ECONNREFUSED)},
	}
	c := &Config{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := tt.err
			if tt.status != 0 {
				cause = &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
					Response: &smithyhttp.Response{Response: &http.Response{StatusCode: tt.status}},
					Err:      tt.err,
				}}
			}
			err := c.WrapError("test", "op", &smithy.OperationError{ServiceID: "SQS", OperationName: "SendMessage", Err: cause})
			assert.Equal(t, tt.permanent, output.IsPermanent(err), "%s: the SDK's retry rule decides, not the HTTP status", err)
		})
	}
}

func TestWrapErrorClassification(t *testing.T) {
	tests := []struct {
		err          error
		name         string
		want         string
		misconfigure bool
		denied       bool // transient for WrapProbeError
	}{
		{name: "invalid client token", err: sdkError(403, "InvalidClientTokenId", "The security token included in the request is invalid."), misconfigure: true,
			want: "test op: HTTP 403 Forbidden: InvalidClientTokenId"},
		{name: "signature mismatch", err: sdkError(403, "SignatureDoesNotMatch", "signature"), misconfigure: true},
		{name: "access denied", err: sdkError(403, "AccessDenied", "Access Denied"), misconfigure: true, denied: true},
		{name: "access denied exception", err: sdkError(400, "AccessDeniedException", "denied"), misconfigure: true, denied: true},
		{name: "unrecognized client", err: sdkError(400, "UnrecognizedClientException", "x"), misconfigure: true},
		{name: "expired token", err: sdkError(400, "ExpiredToken", "x"), misconfigure: true},
		{name: "sns authorization", err: sdkError(403, "AuthorizationError", "x"), misconfigure: true, denied: true},
		{name: "no such bucket", err: sdkError(404, "NoSuchBucket", "The specified bucket does not exist"), misconfigure: true},
		{name: "head bucket not found", err: sdkError(404, "NotFound", "Not Found"), misconfigure: true},
		{name: "head bucket forbidden", err: sdkError(403, "Forbidden", "Forbidden"), misconfigure: true, denied: true, want: "test op: HTTP 403 Forbidden"},
		{name: "head bucket wrong region", err: sdkError(301, "MovedPermanently", "Moved Permanently"), misconfigure: true},
		{name: "queue missing", err: sdkError(400, "AWS.SimpleQueueService.NonExistentQueue", "x"), misconfigure: true},
		{name: "queue missing json", err: sdkError(400, "QueueDoesNotExist", "x"), misconfigure: true},
		{name: "topic missing", err: sdkError(404, "NotFound", "Topic does not exist"), misconfigure: true},
		{name: "kms denied", err: sdkError(400, "KMSAccessDenied", "x"), misconfigure: true, denied: true},
		{name: "throttled", err: sdkError(400, "Throttling", "Rate exceeded")},
		{name: "slow down", err: sdkError(503, "SlowDown", "Please reduce your request rate.")},
		{name: "internal error", err: sdkError(500, "InternalError", "x")},
		{name: "unclassified generic code", err: sdkError(500, "InternalError", "InternalError"), want: "test op: HTTP 500 Internal Server Error"},
		{name: "classified code without status", err: sdkError(0, "Throttling", "bad"), want: "test op: Throttling"},
		{name: "connection refused", err: fmt.Errorf("send: %w", syscall.ECONNREFUSED), want: "test op: connection refused"},
		{name: "deadline", err: fmt.Errorf("canceled: %w", context.DeadlineExceeded), want: "test op: timeout (deadline exceeded)"},
		{name: "credentials", err: errors.New("get identity: failed to refresh cached credentials"), want: "test credentials: request failed"},
		{name: "untrusted certificate", err: fmt.Errorf("tls: %w", x509.UnknownAuthorityError{}), misconfigure: true},
	}
	c := &Config{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.WrapError("test", "op", tt.err)
			require.Error(t, err)
			assert.Equal(t, tt.misconfigure, errors.Is(err, output.ErrMisconfigured), err.Error())
			if tt.want != "" {
				assert.Equal(t, tt.want, err.Error())
			}
			assert.ErrorIs(t, err, tt.err, "the cause stays reachable")

			probe := c.WrapProbeError("test", "op", tt.err)
			assert.Equal(t, tt.misconfigure && !tt.denied, errors.Is(probe, output.ErrMisconfigured), probe.Error())
			assert.Equal(t, err.Error(), probe.Error(), "the probe classifies differently, it reports the same")
		})
	}
}

func TestWrapErrorNil(t *testing.T) {
	assert.NoError(t, (&Config{}).WrapError("test", "op", nil))
}

// Credentials from the default chain are unknown to the driver, so no server text may pass.
func TestWrapErrorNeverCopiesServerText(t *testing.T) {
	const echoed = "AKIAECHOEDBYSERVER01"
	message := echoed
	overridden := echoed
	typed := &sqstypes.InvalidMessageContents{Message: &message}
	for name, err := range map[string]error{
		"message":            sdkError(403, "InvalidAccessKeyId", "key "+echoed+" is invalid"),
		"unrecognized code":  sdkError(400, echoed, "x"),
		"typed sdk error":    &smithy.OperationError{Err: typed},
		"query code header":  &smithy.OperationError{Err: &sqstypes.InvalidMessageContents{ErrorCodeOverride: &overridden}},
		"generic with fault": &smithy.OperationError{Err: &smithy.GenericAPIError{Code: echoed, Message: echoed, Fault: smithy.FaultClient}},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := (&Config{}).WrapError("test", "op", err)
			assert.NotContains(t, fmt.Sprintf("%v %+v %s %q", wrapped, wrapped, wrapped, wrapped), echoed)
		})
	}
	assert.Equal(t, "test op: HTTP 400 Bad Request", (&Config{}).WrapError("test", "op", sdkError(400, echoed, "x")).Error())
	assert.Equal(t, "test op: InvalidMessageContents", (&Config{}).WrapError("test", "op", &smithy.OperationError{Err: typed}).Error())
}

func TestEntryCode(t *testing.T) {
	for code, want := range map[string]string{
		"InvalidMessageContents": "InvalidMessageContents",
		"KmsThrottled":           "KmsThrottled",
		"ThrottlingException":    "ThrottlingException",
		"AKIAECHOEDBYSERVER01":   "unrecognized error code",
		"":                       "unrecognized error code",
	} {
		assert.Equal(t, want, EntryCode(sqs.TypeRegistry, code), code)
	}
}

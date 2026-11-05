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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	maxMessageRunes = 256
	// credentialFailure prefixes SDK errors raised while resolving the
	// credentials of a request, before anything is sent.
	credentialFailure = "get identity:"
)

// misconfigurationCodes are AWS error codes that no retry can fix: rejected
// credentials, and a bucket, queue or topic that does not exist.
var misconfigurationCodes = []string{
	"AuthorizationHeaderMalformed", "ExpiredToken", "ExpiredTokenException", "InvalidAccessKeyId",
	"InvalidClientTokenId", "InvalidSecurity", "InvalidToken", "SignatureDoesNotMatch",
	"UnrecognizedClientException",
	"NoSuchBucket", "PermanentRedirect", "NotFound", "NotFoundException",
	"QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue",
}

// permissionCodes are AWS error codes for a request the credentials may not
// make. They fail delivery; a health check reports them as transient, since
// the probe needs a read permission that delivery does not.
var permissionCodes = []string{
	"AccessDenied", "AccessDeniedException", "AuthorizationError",
	"KMSAccessDenied", "KmsAccessDenied", "KMS.AccessDeniedException",
}

// misconfigurationStatus are HTTP statuses that no retry can fix. Responses
// to HEAD requests carry no error code, only the status.
var misconfigurationStatus = map[int]bool{
	http.StatusMovedPermanently: true,
	http.StatusUnauthorized:     true,
	http.StatusNotFound:         true,
}

// apiError is an AWS error response reduced to its code, status and message.
type apiError struct {
	cause error
	text  string
}

func (e *apiError) Error() string { return e.text }

func (e *apiError) Unwrap() error { return e.cause }

// WrapError turns an AWS SDK error into an error that names the output and
// operation and never carries the configured credentials. Errors that no
// retry can fix, permission denials included, wrap output.ErrMisconfigured.
func (c *Config) WrapError(name, operation string, err error) error {
	return c.wrap(name, operation, err, true)
}

// WrapProbeError is WrapError for health checks: a permission denial, or a
// bare 403 from a HEAD request, stays transient.
func (c *Config) WrapProbeError(name, operation string, err error) error {
	return c.wrap(name, operation, err, false)
}

func (c *Config) wrap(name, operation string, err error, denialIsFatal bool) error {
	if err == nil {
		return nil
	}
	var (
		wrapped error
		status  int
		code    string
	)
	var responseErr *awshttp.ResponseError
	if errors.As(err, &responseErr) {
		status = responseErr.HTTPStatusCode()
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		code = api.ErrorCode()
		text := fmt.Sprintf("%s %s: %s", name, operation, code)
		if status != 0 {
			text += fmt.Sprintf(" (HTTP %d)", status)
		}
		if message := c.redact(api.ErrorMessage()); message != "" && message != code {
			text += ": " + shared.TruncateRunes(message, maxMessageRunes)
		}
		wrapped = &apiError{cause: err, text: text}
	} else {
		if strings.Contains(err.Error(), credentialFailure) {
			operation = "credentials"
		}
		wrapped = shared.WrapDeliveryError(name, operation, err)
	}
	denied := slices.Contains(permissionCodes, code) || (code == "" || code == "Forbidden") && status == http.StatusForbidden
	if slices.Contains(misconfigurationCodes, code) || misconfigurationStatus[status] ||
		denied && denialIsFatal || shared.IsTLSVerificationError(err) {
		return fmt.Errorf("%w: %w", output.ErrMisconfigured, wrapped)
	}
	return wrapped
}

func (c *Config) redact(message string) string {
	for _, secret := range []string{c.SecretAccessKey, c.SessionToken, c.AccessKeyID} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return message
}

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
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	// credentialFailure prefixes the error each generated service client returns when it cannot
	// resolve credentials (service auth.go: fmt.Errorf("get identity: %w", err)); it has no type.
	credentialFailure = "get identity:"
	opCredentials     = "credentials"
)

// misconfigurationCodes are AWS error codes that no retry can fix.
var misconfigurationCodes = []string{
	"AuthorizationHeaderMalformed", "ExpiredToken", "ExpiredTokenException", "InvalidAccessKeyId",
	"InvalidClientTokenId", "InvalidSecurity", "InvalidToken", "SignatureDoesNotMatch",
	"UnrecognizedClientException",
	"NoSuchBucket", "PermanentRedirect", "NotFound", "NotFoundException",
	"QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue",
}

// permissionCodes fail delivery but are transient for a probe, which needs a read permission delivery does not.
var permissionCodes = []string{
	"AccessDenied", "AccessDeniedException", "AuthorizationError",
	"KMSAccessDenied", "KmsAccessDenied", "KMS.AccessDeniedException",
}

// serviceThrottleCodes are transient S3, SQS and SNS client-fault codes missing from the SDK retry lists.
var serviceThrottleCodes = map[string]struct{}{
	"KmsThrottled": {}, "KMSThrottling": {}, "Throttled": {}, "ConcurrentAccess": {}, "OverLimit": {},
}

// sdkRetryable is the standard retryer's decision, extended with serviceThrottleCodes.
var sdkRetryable = retry.IsErrorRetryables(append(slices.Clone(retry.DefaultRetryables),
	retry.RetryableErrorCode{Codes: serviceThrottleCodes}))

// misconfigurationStatus covers HEAD responses, which carry no error code.
var misconfigurationStatus = map[int]bool{
	http.StatusMovedPermanently: true,
	http.StatusUnauthorized:     true,
	http.StatusNotFound:         true,
}

// WrapError reports an AWS failure without server text; unfixable failures and permission denials are misconfigured.
func (c *Config) WrapError(outputName, operation string, err error) error {
	return c.wrap(outputName, operation, err, true)
}

// WrapProbeError is WrapError for health checks: a permission denial or a bare HEAD 403 stays transient.
func (c *Config) WrapProbeError(outputName, operation string, err error) error {
	return c.wrap(outputName, operation, err, false)
}

func (c *Config) wrap(outputName, operation string, err error, denialIsFatal bool) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), credentialFailure) {
		// A denial here comes from STS refusing the role, not from the destination read the probe lacks.
		operation, denialIsFatal = opCredentials, true
	}
	var status int
	if response, ok := errors.AsType[*awshttp.ResponseError](err); ok {
		status = response.HTTPStatusCode()
	}
	api, isAPI := errors.AsType[smithy.APIError](err)
	if !isAPI {
		diagnostic := shared.NewDeliveryError(outputName, operation, err)
		diagnostic.Misconfigured = misconfigurationStatus[status] || shared.IsTLSVerificationError(err)
		return diagnostic
	}
	code := api.ErrorCode()
	denied := slices.Contains(permissionCodes, code) || (code == "" || code == "Forbidden") && status == http.StatusForbidden
	return &shared.DeliveryError{
		Cause:         err,
		Output:        outputName,
		Operation:     operation,
		Code:          printableCode(api),
		Status:        status,
		Misconfigured: slices.Contains(misconfigurationCodes, code) || misconfigurationStatus[status] || denied && denialIsFatal,
		Permanent:     api.ErrorFault() == smithy.FaultClient && sdkRetryable.IsErrorRetryable(err) != aws.TrueTernary,
	}
}

// printableCode names a typed SDK error after its Go type: the SDK chose the type by matching the server
// code against the service model, while ErrorCode can carry a server-supplied override. A generic error
// is named only when its code is one the classification above already knows.
func printableCode(api smithy.APIError) string {
	if _, generic := api.(*smithy.GenericAPIError); !generic {
		return reflect.Indirect(reflect.ValueOf(api)).Type().Name()
	}
	if code := api.ErrorCode(); isClassifiedCode(code) {
		return code
	}
	return ""
}

func isClassifiedCode(code string) bool {
	_, throttle := retry.DefaultThrottleErrorCodes[code]
	_, retryable := retry.DefaultRetryableErrorCodes[code]
	_, service := serviceThrottleCodes[code]
	return throttle || retryable || service || slices.Contains(misconfigurationCodes, code) || slices.Contains(permissionCodes, code)
}

// EntryCode names a per-entry batch failure code when the service model declares it, using registry
// (for example sqs.TypeRegistry); any other code is server text and is withheld.
func EntryCode(registry *smithy.TypeRegistry, code string) string {
	if _, declared := registry.DeserializableError(code); declared || isClassifiedCode(code) {
		return code
	}
	return "unrecognized error code"
}

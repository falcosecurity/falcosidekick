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

package policyreport

import (
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	opWriteReport       = "write report"
	opDiscovery         = "discovery"
	opReadClusterReport = "read clusterreport"
	opResult            = "result"
)

// errResultTooLarge refuses a result that does not fit in a report holding only it.
var errResultTooLarge = &shared.DeliveryError{
	Output: name, Operation: opResult, Permanent: true,
	Code: fmt.Sprintf("cannot fit within the %d-byte report limit", maxReportBytes),
}

// newDeliveryError keeps only the API status: the server message names users and objects.
// The Kubernetes API follows HTTP semantics, so a 4xx other than a conflict or throttling is permanent.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Code != 0 {
		code := int(status.Status().Code)
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: operation, Status: code, Permanent: shared.IsPermanentHTTPStatus(code),
		}
	}
	return shared.NewDeliveryError(name, operation, err)
}

// probeError marks a missing API, rejected credentials, a denied read or an untrusted certificate as misconfigured.
func probeError(operation string, err error) error {
	diagnostic := newDeliveryError(operation, err)
	diagnostic.Misconfigured = apierrors.IsNotFound(err) || apierrors.IsUnauthorized(err) ||
		apierrors.IsForbidden(err) || shared.IsTLSVerificationError(err)
	return diagnostic
}

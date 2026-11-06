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

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	opWriteReport       = "write report"
	opDiscovery         = "discovery"
	opReadClusterReport = "read clusterreport"
)

// newDeliveryError keeps only the API status: the server message names users and objects.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Code != 0 {
		return &shared.DeliveryError{Cause: err, Output: name, Operation: operation, Status: int(status.Status().Code)}
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

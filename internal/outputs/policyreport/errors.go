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
	"io"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// apiError keeps only the status code: the server message names users and objects.
type apiError struct {
	cause     error
	operation string
	code      int32
}

func (e *apiError) Error() string {
	message := fmt.Sprintf("%s %s: HTTP %d", name, e.operation, e.code)
	if text := http.StatusText(int(e.code)); text != "" {
		message += " " + text
	}
	return message
}

// Unwrap returns the original failure for programmatic inspection.
func (e *apiError) Unwrap() error { return e.cause }

// Is matches output.ErrPermanent for 4xx answers a retry cannot change; a 409 conflict can resolve on retry.
func (e *apiError) Is(target error) bool {
	return target == output.ErrPermanent && e.code != http.StatusConflict && shared.IsPermanentHTTPStatus(int(e.code))
}

// Format keeps diagnostic formatting from exposing the wrapped cause.
func (e *apiError) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", e.Error())
		return
	}
	_, _ = io.WriteString(state, e.Error())
}

// safeError wraps err with a diagnostic that copies no server or transport text.
func safeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Code != 0 {
		return &apiError{operation: operation, code: status.Status().Code, cause: err}
	}
	return shared.WrapDeliveryError(name, operation, err)
}

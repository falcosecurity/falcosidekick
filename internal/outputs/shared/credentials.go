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
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// CredentialHeader describes a credential that an output sends in a header
// of its own, such as an API key.
type CredentialHeader struct {
	// Field is the config key holding the credential, e.g. "api_key".
	Field string
	// Header carries the credential, e.g. "Authorization" or "DD-API-KEY".
	Header string
	// Required rejects an empty value.
	Required bool
}

// ValidateCredential checks a credential sent in its own header. A set
// value must be a valid header value. With the Authorization header, a set
// value cannot be combined with basic auth, bearer_token or an
// Authorization entry in headers. Any other header belongs to the output,
// so headers may never set it.
func (c *HTTPConfig) ValidateCredential(h CredentialHeader, value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	set := value != ""
	switch {
	case set && strings.TrimSpace(value) == "", !set && h.Required:
		errs.Add(h.Field, "is required")
	case set && !httpguts.ValidHeaderFieldValue(value):
		errs.Add(h.Field, "invalid header value")
	}
	authorization := strings.EqualFold(h.Header, "Authorization")
	if authorization && set && (c.Username != "" || c.Password != "" || c.BearerToken != "") {
		errs.Add(h.Field, "cannot combine "+h.Field+" with basic auth or bearer_token")
	}
	for name := range c.Headers {
		if !strings.EqualFold(name, h.Header) {
			continue
		}
		switch {
		case !authorization:
			errs.Add(h.Field, "cannot be combined with a "+h.Header+" header")
		case set:
			errs.Add(h.Field, "cannot combine "+h.Field+" with an authorization header")
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

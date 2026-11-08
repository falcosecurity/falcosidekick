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
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func validateHeaderNames(headers map[string]ValueSources) error {
	seen := make(map[string]bool, len(headers))
	for _, name := range slices.Sorted(maps.Keys(headers)) {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("invalid header name")
		}
		canonical := http.CanonicalHeaderKey(name)
		if seen[canonical] {
			return fmt.Errorf("duplicate header name %q", canonical)
		}
		seen[canonical] = true
		switch canonical {
		case "Host", "Content-Length", "Transfer-Encoding", "Trailer", "Connection",
			"Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
			"Te", "Upgrade", "Content-Encoding", "Accept-Encoding":
			return fmt.Errorf("header %q is owned by the HTTP transport", canonical)
		}
	}
	return nil
}

func (c *HTTPConfig) validateHeaders() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if err := validateHeaderNames(c.Headers); err != nil {
		errs.Add("headers", err.Error())
		return errs
	}
	for _, name := range slices.Sorted(maps.Keys(c.Headers)) {
		h := c.Headers[name]
		field := fmt.Sprintf("headers[%q]", name)
		if strings.EqualFold(name, "Authorization") {
			if len(h.Values) > 0 {
				errs.Add(field, "authorization must use secrets or files, not public values")
			}
			if c.Username != "" || c.Password != "" || c.BearerToken != "" {
				errs.Add(field, "cannot combine authorization with basic auth or bearer_token")
			}
		}
		if _, err := h.resolve(); err != nil {
			errs.Add(field, err.Error())
		}
	}
	return errs
}

func (h ValueSources) resolve() ([]string, error) {
	return h.resolveSources("header", httpguts.ValidHeaderFieldValue)
}

// ApplyHeaders replaces configured request headers in values, secrets, files order.
// It leaves the request unchanged if any header cannot be resolved or validated.
func ApplyHeaders(req *http.Request, headers map[string]ValueSources) error {
	if err := validateHeaderNames(headers); err != nil {
		return err
	}
	resolved := make(http.Header, len(headers))
	for _, name := range slices.Sorted(maps.Keys(headers)) {
		values, err := headers[name].resolve()
		if err != nil {
			return fmt.Errorf("headers[%q]: %w", name, err)
		}
		if len(values) > 0 {
			resolved[http.CanonicalHeaderKey(name)] = values
		}
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for name := range req.Header {
		if _, ok := resolved[http.CanonicalHeaderKey(name)]; ok {
			delete(req.Header, name)
		}
	}
	maps.Copy(req.Header, resolved)
	return nil
}

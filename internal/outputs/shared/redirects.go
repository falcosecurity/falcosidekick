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
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type redirectError struct {
	reason string
}

func (e *redirectError) Error() string {
	return e.reason
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || req.Response == nil {
		return &redirectError{reason: "invalid redirect chain"}
	}
	if len(via) >= 10 {
		return &redirectError{reason: "redirect request limit exceeded"}
	}
	original := via[0]
	origin, valid := normalizeOrigin(original.URL)
	destination, destinationValid := normalizeOrigin(req.URL)
	if !valid || !destinationValid {
		return &redirectError{reason: "invalid redirect origin"}
	}
	if origin != destination {
		return &redirectError{reason: "cross-origin redirect denied"}
	}
	if req.URL.User != nil && req.URL.User.String() != original.URL.User.String() {
		return &redirectError{reason: "redirect credentials changed"}
	}

	method := original.Method
	if method == "" {
		method = http.MethodGet
	}
	hasBody := original.Body != nil && original.Body != http.NoBody
	switch req.Response.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		if method != http.MethodGet && method != http.MethodHead || hasBody || req.Method != method {
			return &redirectError{reason: "redirect would change delivery method or body"}
		}
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		if req.Method != method || hasBody && (req.Body == nil || req.Body == http.NoBody || req.ContentLength != original.ContentLength) {
			return &redirectError{reason: "redirect would change delivery method or body"}
		}
	default:
		return &redirectError{reason: "unsupported redirect status"}
	}

	// Restore the resolved snapshot only after the origin check. Equivalent host
	// spellings can otherwise lose credentials; generated Referer can leak URLs.
	req.Header = original.Header.Clone() //nolint:gosec // G119: scheme, canonical host and effective port match via[0] before restoring credentials.
	return nil
}

type httpOrigin struct {
	scheme string
	host   string
	port   uint16
}

func normalizeOrigin(u *url.URL) (httpOrigin, bool) {
	if u == nil || u.Opaque != "" || u.Host == "" {
		return httpOrigin{}, false
	}
	origin := httpOrigin{scheme: strings.ToLower(u.Scheme)}
	switch origin.scheme {
	case schemeHTTP:
		origin.port = 80
	case schemeHTTPS:
		origin.port = 443
	default:
		return httpOrigin{}, false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return httpOrigin{}, false
		}
		origin.port = uint16(n)
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is6() != strings.HasPrefix(u.Host, "[") {
			return httpOrigin{}, false
		}
		origin.host = addr.String()
	} else {
		if strings.HasPrefix(u.Host, "[") {
			return httpOrigin{}, false
		}
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil || ascii == "" {
			return httpOrigin{}, false
		}
		origin.host = strings.ToLower(ascii)
	}
	return origin, true
}

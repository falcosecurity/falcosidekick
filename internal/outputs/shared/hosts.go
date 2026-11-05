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
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var endpointRegex = regexp.MustCompile(`^/[\w/.%:@!$&'()*+,;=-]*$`)

// Validation messages never include the value or url.Parse causes: URLs can carry credentials.

// ValidateEndpoint checks that a value is a valid HTTP path.
func ValidateEndpoint(value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if value == "" {
		return errs
	}
	if !validPath(value) {
		errs.Add("", "must be a valid path starting with / (e.g. /api/v1)")
	}
	return errs
}

func validPath(value string) bool {
	if !endpointRegex.MatchString(value) {
		return false
	}
	_, err := url.PathUnescape(value)
	return err == nil
}

// ValidateOrigin checks that a value is exactly http(s)://host[:port].
func ValidateOrigin(value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if value == "" {
		errs.Add("", "is required")
		return errs
	}
	if problem := originProblem(value); problem != "" {
		errs.Add("", problem)
	}
	return errs
}

// ValidateBrokers checks that brokers is non-empty and each entry is host:port.
func ValidateBrokers(brokers []string) utils.ValidationErrors {
	return validateHosts(brokers, brokerProblem)
}

// ValidateOrigins checks that hosts is non-empty and each entry passes ValidateOrigin.
func ValidateOrigins(hosts []string) utils.ValidationErrors {
	return validateHosts(hosts, originProblem)
}

func validateHosts(hosts []string, problemOf func(string) string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if len(hosts) == 0 {
		errs.Add("", "is required")
		return errs
	}
	for i, h := range hosts {
		if h == "" {
			errs.Add("", fmt.Sprintf("entry [%d] must not be empty", i))
			continue
		}
		if problem := problemOf(h); problem != "" {
			errs.Add("", fmt.Sprintf("entry [%d] %s", i, problem))
		}
	}
	return errs
}

func parseHost(value string) (host *url.URL, problem string) {
	host, err := url.Parse(value)
	if err != nil {
		return nil, "invalid URL"
	}
	if host.Scheme == "" || host.Host == "" {
		return nil, "must include scheme and host (e.g. https://host:port)"
	}
	return host, ""
}

func brokerProblem(value string) string {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(host, "/?#@") {
		return "must be host:port without a scheme (e.g. server.example:9092)"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "port must be between 1 and 65535"
	}
	return ""
}

func originProblem(value string) string {
	u, problem := parseHost(value)
	if problem != "" {
		return problem
	}
	if u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return "scheme must be http or https"
	}
	if u.User != nil {
		return "must not include credentials; use username/password or bearer_token"
	}
	if u.Path != "" || strings.ContainsAny(value, "?#") {
		return "must be scheme, host and port only; use base_path, endpoint or query_params"
	}
	return ""
}

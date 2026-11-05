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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCredential(t *testing.T) {
	authorization := CredentialHeader{Field: "api_key", Header: "Authorization"}
	required := CredentialHeader{Field: "api_key", Header: "Authorization", Required: true}
	own := CredentialHeader{Field: "app_key", Header: "DD-APPLICATION-KEY"}
	tests := []struct {
		cfg   HTTPConfig
		name  string
		value string
		want  string
		h     CredentialHeader
	}{
		{name: "optional unset", h: authorization},
		{name: "optional set", h: authorization, value: "k"},
		{name: "required unset", h: required, want: "api_key: is required"},
		{name: "blank", h: authorization, value: "  ", want: "api_key: is required"},
		{name: "invalid header value", h: authorization, value: "k\r\nX: y", want: "api_key: invalid header value"},
		{name: "with basic auth", h: authorization, value: "k", cfg: HTTPConfig{Username: "u"}, want: "cannot combine api_key with basic auth or bearer_token"},
		{name: "with bearer", h: authorization, value: "k", cfg: HTTPConfig{BearerToken: "b"}, want: "cannot combine api_key with basic auth or bearer_token"},
		{name: "authorization header with key", h: authorization, value: "k",
			cfg:  HTTPConfig{Headers: map[string]ValueSources{"authorization": {Values: []string{"x"}}}},
			want: "cannot combine api_key with an authorization header"},
		{name: "authorization header without key", h: authorization,
			cfg: HTTPConfig{Headers: map[string]ValueSources{"Authorization": {Values: []string{"x"}}}}},
		{name: "basic auth without key", h: authorization, cfg: HTTPConfig{Username: "u"}},
		{name: "own header always rejected", h: own,
			cfg:  HTTPConfig{Headers: map[string]ValueSources{"dd-application-key": {Secrets: []string{"x"}}}},
			want: "app_key: cannot be combined with a DD-APPLICATION-KEY header"},
		{name: "own header ignores basic auth", h: own, value: "k", cfg: HTTPConfig{Username: "u"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.ValidateCredential(tt.h, tt.value)
			if tt.want == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Contains(t, errs.Error(), tt.want)
		})
	}
}

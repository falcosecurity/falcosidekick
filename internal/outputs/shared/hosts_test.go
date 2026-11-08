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

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"https", "https://example.com", false},
		{"http with port", "http://localhost:9200", false},
		{"ipv6", "http://[::1]:9200", false},
		{"empty", "", true},
		{"no scheme", "example.com", true},
		{"no host", "http://", true},
		{"relative path", "/api/v1", true},
		{"other scheme", "ftp://example.com", true},
		{"credentials", "https://u:p@example.com", true},
		{"path", "http://host:9200/api", true},
		{"trailing slash", "http://host:9200/", true},
		{"query", "http://host:9200?token=x", true},
		{"empty query", "http://host:9200?", true},
		{"fragment", "http://host:9200#x", true},
		{"bad port", "http://host:port", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantErr, len(ValidateOrigin(tt.value)) > 0)
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		ep      string
		wantErr bool
	}{
		{"valid path", "/api/v1", false},
		{"valid with dots", "/api/v2/alerts", false},
		{"root", "/", false},
		{"empty allowed", "", false},
		{"no leading slash", "api/v1", true},
		{"spaces", "/api v1", true},
		{"backslash", "/api\\v1", true},
		{"query", "/api?x=1", true},
		{"fragment", "/api#x", true},
		{"bad escape", "/api%zz", true},
		{"valid escape", "/api%20v1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateEndpoint(tt.ep)
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateBrokers(t *testing.T) {
	tests := []struct {
		name    string
		brokers []string
		wantErr bool
	}{
		{"single", []string{"kafka:9092"}, false},
		{"multiple", []string{"a:9092", "b:9093"}, false},
		{"ip", []string{"10.0.0.1:9092"}, false},
		{"ipv6", []string{"[::1]:9092"}, false},
		{"nil", nil, true},
		{"empty slice", []string{}, true},
		{"empty entry", []string{""}, true},
		{"no port", []string{"kafka"}, true},
		{"no host", []string{":9092"}, true},
		{"scheme", []string{"http://kafka:9092"}, true},
		{"path", []string{"kafka:9092/x"}, true},
		{"credentials", []string{"u:p@kafka:9092"}, true},
		{"named port", []string{"kafka:plain"}, true},
		{"port zero", []string{"kafka:0"}, true},
		{"port too high", []string{"kafka:65536"}, true},
		{"mixed", []string{"kafka:9092", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantErr, len(ValidateBrokers(tt.brokers)) > 0)
		})
	}
}

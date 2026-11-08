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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestValidateTLSServerEnabled(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = &core.TLSConfig{

		Enabled: true,
	}

	errs := cfg.Validate()
	assert.NotEmpty(t, errs, "server TLS enabled without cert/key should fail")
}

func TestValidateTLSServerWithFiles(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = &core.TLSConfig{

		Enabled:  true,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	errs := cfg.Validate()
	assert.NotEmpty(t, errs, "TLS with nonexistent files should fail")
	assert.GreaterOrEqual(t, len(errs), 2)
}

func TestValidateTLSDisabledPassesWithoutFiles(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = &core.TLSConfig{
		Enabled: false,
	}

	errs := cfg.Validate()
	assert.Empty(t, errs)
}

func TestValidateTLSServerMutualTLSRequiresCA(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = &core.TLSConfig{

		Enabled:   true,
		MutualTLS: true,
		CertFile:  "/nonexistent/cert.pem",
		KeyFile:   "/nonexistent/key.pem",
	}

	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if e.Field == "tls.ca_file" || e.Field == "ca_file" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected cacertfile error for server mutual TLS, got: %v", errs)
}

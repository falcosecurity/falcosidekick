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
	"fmt"
	"os"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func validateTLS(ts *core.TLSConfig) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if ts.Enabled {
		if ts.CertFile == "" {
			errs.Add("cert_file", "must be specified when TLS is enabled")
		} else if _, err := os.Stat(ts.CertFile); err != nil {
			errs.Add("cert_file", fmt.Sprintf("file does not exist: %v", err))
		}
		if ts.KeyFile == "" {
			errs.Add("key_file", "must be specified when TLS is enabled")
		} else if _, err := os.Stat(ts.KeyFile); err != nil {
			errs.Add("key_file", fmt.Sprintf("file does not exist: %v", err))
		}
		if ts.MutualTLS {
			if ts.CACertFile == "" {
				errs.Add("ca_file", "must be specified when mutual TLS is enabled")
			} else if _, err := os.Stat(ts.CACertFile); err != nil {
				errs.Add("ca_file", fmt.Sprintf("file does not exist: %v", err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

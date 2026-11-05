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

// Package awstest provides test helpers for the AWS outputs.
package awstest

import (
	"maps"
	"path/filepath"
	"testing"
)

// Test credentials accepted by the fake servers; never valid on AWS.
const (
	AccessKeyID     = "AKIAFAKEACCESSKEY001"
	SecretAccessKey = "fake/secret+access+key/value/0000000000"
	SessionToken    = "fake-session-token-value-0000"
	Region          = "eu-west-1"
)

// Isolate clears the AWS environment and shared config files so the host cannot change a test.
func Isolate(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ENDPOINT_URL",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// Config returns an output configuration with the test credentials, the endpoint, and extra merged over them.
func Config(endpoint string, extra map[string]any) map[string]any {
	cfg := map[string]any{
		"region":            Region,
		"access_key_id":     AccessKeyID,
		"secret_access_key": SecretAccessKey,
		"session_token":     SessionToken,
	}
	if endpoint != "" {
		cfg["endpoint"] = endpoint
	}
	maps.Copy(cfg, extra)
	return cfg
}

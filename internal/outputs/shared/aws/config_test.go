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

package aws

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws/awstest"
)

func TestSchemaFieldsMarkCredentialsSecret(t *testing.T) {
	secret := map[string]bool{}
	for _, f := range SchemaFields() {
		secret[f.Name] = f.Secret
	}
	for _, name := range []string{"access_key_id", "secret_access_key", "session_token"} {
		assert.True(t, secret[name], name)
	}
	for _, name := range []string{"region", "role_arn", "external_id", "endpoint", "tls.ca_file"} {
		v, ok := secret[name]
		assert.True(t, ok, name)
		assert.False(t, v, name)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     Config
	}{
		{name: "empty uses the default chain", cfg: Config{}},
		{name: "static keys", cfg: Config{AccessKeyID: "a", SecretAccessKey: "s", SessionToken: "t"}},
		{name: "role with external id", cfg: Config{RoleARN: "arn:aws:iam::123456789012:role/falco", ExternalID: "ext-id"}},
		{name: "endpoint with trailing slash", cfg: Config{Endpoint: "http://localhost:4566/"}},
		{name: "bad region", cfg: Config{Region: "EU WEST"}, wantErr: "region: invalid region"},
		{name: "key without secret", cfg: Config{AccessKeyID: "a"}, wantErr: "secret_access_key: is required when access_key_id is set"},
		{name: "secret without key", cfg: Config{SecretAccessKey: "s"}, wantErr: "access_key_id: is required when secret_access_key is set"},
		{name: "token without keys", cfg: Config{SessionToken: "t"}, wantErr: "session_token: requires access_key_id"},
		{name: "role arn of another service", cfg: Config{RoleARN: "arn:aws:sns:us-east-1:123456789012:topic"}, wantErr: "role_arn: must be an IAM role ARN"},
		{name: "role arn of a user", cfg: Config{RoleARN: "arn:aws:iam::123456789012:user/falco"}, wantErr: "role_arn: must be an IAM role ARN"},
		{name: "role arn not an arn", cfg: Config{RoleARN: "falco"}, wantErr: "role_arn: must be an IAM role ARN"},
		{name: "external id without role", cfg: Config{ExternalID: "ext-id"}, wantErr: "external_id: requires role_arn"},
		{name: "external id too short", cfg: Config{RoleARN: "arn:aws:iam::123456789012:role/falco", ExternalID: "x"}, wantErr: "external_id: must be 2 to 1224"},
		{name: "endpoint without scheme", cfg: Config{Endpoint: "localhost:4566"}, wantErr: "endpoint: must be an http or https URL"},
		{name: "endpoint ftp", cfg: Config{Endpoint: "ftp://host"}, wantErr: "endpoint: must be an http or https URL"},
		{name: "endpoint without host", cfg: Config{Endpoint: "http://"}, wantErr: "endpoint: must include a host"},
		{name: "endpoint with credentials", cfg: Config{Endpoint: "http://user:pass@host"}, wantErr: "endpoint: must not include credentials"},
		{name: "endpoint with path", cfg: Config{Endpoint: "http://host/path"}, wantErr: "endpoint: must be scheme, host and port only"},
		{name: "endpoint with query", cfg: Config{Endpoint: "http://host?x=1"}, wantErr: "endpoint: must be scheme, host and port only"},
		{name: "endpoint invalid", cfg: Config{Endpoint: "http://[::1"}, wantErr: "endpoint: invalid URL"},
		{name: "tls cert without key", cfg: Config{TLS: shared.TLSClientConfig{CertFile: "/missing"}}, wantErr: "tls.key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.Empty(t, errs)
				return
			}
			require.NotEmpty(t, errs)
			assert.Contains(t, errs.Error(), tt.wantErr)
		})
	}
}

func TestLoadRegion(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback string
		want     string
		wantErr  string
		cfg      Config
	}{
		{name: "explicit wins", cfg: Config{Region: "eu-west-1"}, env: "us-east-1", fallback: "ap-south-1", want: "eu-west-1"},
		{name: "environment before fallback", env: "us-east-1", fallback: "ap-south-1", want: "us-east-1"},
		{name: "fallback", fallback: "ap-south-1", want: "ap-south-1"},
		{name: "none", wantErr: "region: is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awstest.Isolate(t)
			t.Setenv("AWS_REGION", tt.env)
			cfg, err := tt.cfg.Load(context.Background(), tt.fallback)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.Region)
		})
	}
}

func TestLoadSharedConfigError(t *testing.T) {
	awstest.Isolate(t)
	t.Setenv("AWS_PROFILE", "absent")
	_, err := (&Config{Region: "eu-west-1"}).Load(context.Background(), "")
	require.Error(t, err)
	assert.Equal(t, "cannot load the AWS shared configuration", err.Error())
}

func TestLoadTLSError(t *testing.T) {
	awstest.Isolate(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, []byte("not a certificate"), 0o600))
	_, err := (&Config{Region: "eu-west-1", TLS: shared.TLSClientConfig{CAFile: ca}}).Load(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls:")
}

func TestLoadStaticCredentials(t *testing.T) {
	awstest.Isolate(t)
	c := Config{Region: "eu-west-1", AccessKeyID: "AKIA", SecretAccessKey: "secret", SessionToken: "token", Endpoint: "http://localhost:4566/"}
	cfg, err := c.Load(context.Background(), "")
	require.NoError(t, err)
	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIA", creds.AccessKeyID)
	assert.Equal(t, "secret", creds.SecretAccessKey)
	assert.Equal(t, "token", creds.SessionToken)
	require.NotNil(t, cfg.BaseEndpoint)
	assert.Equal(t, "http://localhost:4566", *cfg.BaseEndpoint)
	require.NotNil(t, cfg.Retryer)
	assert.Equal(t, 1, cfg.Retryer().MaxAttempts(), "the pipeline owns retries")
}

// The custom endpoint reaches STS only through the SDK environment, as set here.
func TestLoadAssumeRole(t *testing.T) {
	awstest.Isolate(t)
	var form string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm.Encode()
		assert.Contains(t, r.Header.Get("Authorization"), "Credential=AKIABASE/")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>ASIAROLE</AccessKeyId><SecretAccessKey>rolesecret</SecretAccessKey><SessionToken>roletoken</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/falco/falcosidekick</Arn><AssumedRoleId>AROA:falcosidekick</AssumedRoleId></AssumedRoleUser>
</AssumeRoleResult></AssumeRoleResponse>`))
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)

	c := Config{
		Region: "eu-west-1", AccessKeyID: "AKIABASE", SecretAccessKey: "base",
		RoleARN: "arn:aws:iam::123456789012:role/falco", ExternalID: "ext-id",
		Endpoint: "http://service.invalid:1",
	}
	cfg, err := c.Load(context.Background(), "")
	require.NoError(t, err)
	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ASIAROLE", creds.AccessKeyID)
	assert.Contains(t, form, "Action=AssumeRole")
	assert.Contains(t, form, "ExternalId=ext-id")
	assert.Contains(t, form, "RoleSessionName="+RoleSessionName)
	assert.Contains(t, form, "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ffalco")
}

// STS is built after the retry policy: a failed AssumeRole is one request, and the pipeline retries.
func TestLoadAssumeRoleIsNotRetriedByTheSDK(t *testing.T) {
	awstest.Isolate(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Receiver</Type><Code>ServiceUnavailable</Code></Error></ErrorResponse>`))
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)

	c := Config{Region: "eu-west-1", AccessKeyID: "AKIABASE", SecretAccessKey: "base", RoleARN: "arn:aws:iam::123456789012:role/falco"}
	cfg, err := c.Load(context.Background(), "")
	require.NoError(t, err)
	_, err = cfg.Credentials.Retrieve(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

// IRSA builds its STS client inside the default chain: it must get the same transport and retry policy.
func TestLoadWebIdentityIsNotRetriedByTheSDK(t *testing.T) {
	awstest.Isolate(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Receiver</Type><Code>ServiceUnavailable</Code></Error></ErrorResponse>`))
	}))
	t.Cleanup(server.Close)
	token := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(token, []byte("web-identity-token"), 0o600))
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/falco")

	cfg, err := (&Config{Region: "eu-west-1"}).Load(context.Background(), "")
	require.NoError(t, err)
	_, err = cfg.Credentials.Retrieve(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

// tls.ca_file trusts a private CA for the destination only. STS has a public certificate: when
// the credential calls shared the output's CA pool, IRSA with a private endpoint could not start.
func TestLoadKeepsTheOutputTLSOffTheCredentialCalls(t *testing.T) {
	awstest.Isolate(t)
	var stsCalls atomic.Int32
	stsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		stsCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(stsServer.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stsServer.Certificate().Raw}), 0o600))
	token := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(token, []byte("web-identity-token"), 0o600))
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/falco")

	cfg, err := (&Config{Region: "eu-west-1", TLS: shared.TLSClientConfig{CAFile: caFile}}).Load(context.Background(), "")
	require.NoError(t, err)
	_, err = cfg.Credentials.Retrieve(context.Background())
	require.Error(t, err)
	assert.ErrorAs(t, err, new(*tls.CertificateVerificationError), "the credential client trusts the system roots, not the output's CA")
	assert.Zero(t, stsCalls.Load())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, stsServer.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := cfg.HTTPClient.Do(req)
	require.NoError(t, err, "the service client trusts the output's CA")
	_ = resp.Body.Close()
}

func TestLoadRefusesCrossOriginRedirect(t *testing.T) {
	awstest.Isolate(t)
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	t.Cleanup(other.Close)
	service := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusTemporaryRedirect))
	t.Cleanup(service.Close)

	c := Config{Region: "eu-west-1", AccessKeyID: "AKIABASE", SecretAccessKey: "base", Endpoint: service.URL}
	cfg, err := c.Load(context.Background(), "")
	require.NoError(t, err)
	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	require.Error(t, err)
	// net/http returns the refused redirect response with the policy error; the SDK reports the response.
	assert.Equal(t, "awstest GetCallerIdentity: HTTP 307 Temporary Redirect", c.WrapError("awstest", "GetCallerIdentity", err).Error())
	assert.Zero(t, redirected.Load(), "signed requests never reach another origin")
}

func TestLoadAssumeRoleRejected(t *testing.T) {
	awstest.Isolate(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform sts:AssumeRole</Message></Error><RequestId>r</RequestId></ErrorResponse>`))
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)

	c := Config{Region: "eu-west-1", AccessKeyID: "AKIABASE", SecretAccessKey: "base-secret-value", RoleARN: "arn:aws:iam::123456789012:role/falco"}
	cfg, err := c.Load(context.Background(), "")
	require.NoError(t, err)
	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	wrapped := c.WrapError("awstest", "GetCallerIdentity", err)
	require.Error(t, wrapped)
	assert.ErrorIs(t, wrapped, output.ErrMisconfigured)
	assert.Contains(t, wrapped.Error(), "AccessDenied")
	for _, secret := range []string{"AKIABASE", "base-secret-value"} {
		assert.False(t, strings.Contains(wrapped.Error(), secret), wrapped.Error())
	}
}

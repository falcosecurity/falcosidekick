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
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	// RoleSessionName names the sessions opened with role_arn.
	RoleSessionName = "falcosidekick"
	// requestTimeout bounds one AWS API call, including the response body.
	requestTimeout = 30 * time.Second
)

var (
	regionPattern     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)
	externalIDPattern = regexp.MustCompile(`^[\w+=,.@:/-]+$`)
)

// Config is the AWS part of an output configuration.
type Config struct {
	Region          string                 `mapstructure:"region"`
	AccessKeyID     string                 `mapstructure:"access_key_id"`
	SecretAccessKey string                 `mapstructure:"secret_access_key"`
	SessionToken    string                 `mapstructure:"session_token"`
	RoleARN         string                 `mapstructure:"role_arn"`
	ExternalID      string                 `mapstructure:"external_id"`
	Endpoint        string                 `mapstructure:"endpoint"`
	TLS             shared.TLSClientConfig `mapstructure:"tls"`
}

// SchemaFields returns the schema of the fields in Config.
func SchemaFields() []output.SchemaField {
	return append([]output.SchemaField{
		{Name: "region", Type: "string", Label: "AWS Region (default from the environment or the resource)"},
		{Name: "access_key_id", Type: "string", Secret: true, Label: "Access Key ID (default credential chain when empty)"},
		{Name: "secret_access_key", Type: "string", Secret: true, Label: "Secret Access Key"},
		{Name: "session_token", Type: "string", Secret: true, Label: "Session Token"},
		{Name: "role_arn", Type: "string", Label: "Role ARN to assume"},
		{Name: "external_id", Type: "string", Label: "External ID for the assumed role"},
		{Name: "endpoint", Type: "string", Label: "Custom Endpoint (scheme, host and port)"},
	}, shared.TLSClientSchemaFields()...)
}

// Validate checks the fields that need no AWS lookup.
func (c *Config) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Region != "" && !regionPattern.MatchString(c.Region) {
		errs.Add("region", "invalid region")
	}
	switch {
	case c.AccessKeyID != "" && c.SecretAccessKey == "":
		errs.Add("secret_access_key", "is required when access_key_id is set")
	case c.AccessKeyID == "" && c.SecretAccessKey != "":
		errs.Add("access_key_id", "is required when secret_access_key is set")
	}
	if c.SessionToken != "" && c.AccessKeyID == "" {
		errs.Add("session_token", "requires access_key_id and secret_access_key")
	}
	if c.RoleARN != "" {
		if role, err := arn.Parse(c.RoleARN); err != nil || role.Service != "iam" || !strings.HasPrefix(role.Resource, "role/") {
			errs.Add("role_arn", "must be an IAM role ARN (arn:aws:iam::ACCOUNT:role/NAME)")
		}
	}
	if c.ExternalID != "" {
		if c.RoleARN == "" {
			errs.Add("external_id", "requires role_arn")
		} else if len(c.ExternalID) < 2 || len(c.ExternalID) > 1224 || !externalIDPattern.MatchString(c.ExternalID) {
			errs.Add("external_id", "must be 2 to 1224 characters of letters, digits and +=,.@:/-_")
		}
	}
	if c.Endpoint != "" {
		if problem := endpointProblem(c.Endpoint); problem != "" {
			errs.Add("endpoint", problem)
		}
	}
	errs.Merge("tls", c.TLS.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func endpointProblem(value string) string {
	u, err := url.Parse(value)
	switch {
	case err != nil:
		return "invalid URL"
	case u.Scheme != "http" && u.Scheme != "https":
		return "must be an http or https URL"
	case u.Host == "":
		return "must include a host"
	case u.User != nil:
		return "must not include credentials"
	case strings.TrimSuffix(u.Path, "/") != "" || strings.ContainsAny(value, "?#"):
		return "must be scheme, host and port only"
	}
	return ""
}

// Load resolves the region and the credentials; SDK retries are off because the pipeline owns retries.
func (c *Config) Load(ctx context.Context, fallbackRegion string) (sdkaws.Config, error) {
	// Both clients apply the proxy and the redirect policy of every HTTP output. The output's tls
	// settings are for the destination service only: STS has a public certificate.
	service, err := shared.BuildHTTPClient(&shared.HTTPConfig{TLS: c.TLS})
	if err != nil {
		return sdkaws.Config{}, err
	}
	service.Timeout = requestTimeout
	credentialClient, err := shared.BuildHTTPClient(&shared.HTTPConfig{})
	if err != nil {
		return sdkaws.Config{}, err
	}
	credentialClient.Timeout = requestTimeout
	// Passed as load options, so the STS clients the default chain builds (IRSA, profiles) use them too.
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithHTTPClient(credentialClient),
		awsconfig.WithRetryer(func() sdkaws.Retryer { return sdkaws.NopRetryer{} }),
	}
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	if c.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return sdkaws.Config{}, errors.New("cannot load the AWS shared configuration")
	}
	if base.Region == "" {
		base.Region = fallbackRegion
	}
	if base.Region == "" {
		return sdkaws.Config{}, errors.New("region: is required (set region or AWS_REGION)")
	}

	cfg := base.Copy()
	if c.RoleARN != "" {
		// STS shares the transport and the retry policy; endpoint names the destination service, not STS.
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg.Copy()), c.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = RoleSessionName
			if c.ExternalID != "" {
				o.ExternalID = sdkaws.String(c.ExternalID)
			}
		})
		cfg.Credentials = sdkaws.NewCredentialsCache(provider)
	}
	if c.Endpoint != "" {
		cfg.BaseEndpoint = sdkaws.String(strings.TrimSuffix(c.Endpoint, "/"))
	}
	cfg.HTTPClient = serviceClient{Client: service, credentials: credentialClient}
	return cfg, nil
}

// serviceClient sends the destination requests; closing its idle connections also closes those
// of the credential client, which the service client's Options() does not expose.
type serviceClient struct {
	*http.Client
	credentials *http.Client
}

func (c serviceClient) CloseIdleConnections() {
	c.Client.CloseIdleConnections()
	c.credentials.CloseIdleConnections()
}

// CloseIdleConnections releases the idle connections of the HTTP client Load configured,
// as a service client reports it in Options().HTTPClient.
func CloseIdleConnections(client interface {
	Do(*http.Request) (*http.Response, error)
},
) {
	if closer, ok := client.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

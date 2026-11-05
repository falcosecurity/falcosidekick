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

package gcppubsub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "gcppubsub"

	// closeTimeout bounds the flush of buffered messages on Close.
	closeTimeout = 10 * time.Second

	// Resource limits: https://cloud.google.com/pubsub/quotas#resource_limits
	maxAttributes        = 100
	maxAttributeKeyBytes = 256
	maxAttributeValBytes = 1024
	reservedPrefix       = "goog"
)

// Topic IDs: https://cloud.google.com/pubsub/docs/pubsub-basics#resource_names
var topicID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._~%+-]{2,254}$`)

// credentialTypes are the Google credential JSON types the output loads.
var credentialTypes = map[string]option.CredentialsType{
	string(option.ServiceAccount):             option.ServiceAccount,
	string(option.AuthorizedUser):             option.AuthorizedUser,
	string(option.ImpersonatedServiceAccount): option.ImpersonatedServiceAccount,
	string(option.ExternalAccount):            option.ExternalAccount,
}

type config struct {
	CustomAttributes map[string]string `mapstructure:"custom_attributes"`
	ProjectID        string            `mapstructure:"project_id"`
	Topic            string            `mapstructure:"topic"`
	Credentials      string            `mapstructure:"credentials"`
	Endpoint         string            `mapstructure:"endpoint"`
	EmulatorHost     string            `mapstructure:"emulator_host"`
	credentialsType  option.CredentialsType
	credentialsJSON  []byte
	Runtime          output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Google Cloud Pub/Sub output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "queue",
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "project_id", Type: "string", Required: true, Label: "Project ID"},
			{Name: "topic", Type: "string", Required: true, Label: "Topic ID"},
			{Name: "credentials", Type: "string", Secret: true, Label: "Credentials JSON, raw or base64 (default: Application Default Credentials)"},
			{Name: "custom_attributes", Type: "map", Label: "Message attributes"},
			{Name: "endpoint", Type: "string", Label: "gRPC endpoint host:port (TLS)"},
			{Name: "emulator_host", Type: "string", Label: "Emulator host:port (plaintext, no authentication)"},
		}, shared.RuntimeConfigSchemaFields()...),
	},
}

type driver struct {
	client    *pubsub.Client
	publisher *pubsub.Publisher
	cfg       config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	switch {
	case strings.TrimSpace(c.ProjectID) == "":
		errs.Add("project_id", "is required")
	case strings.ContainsAny(c.ProjectID, "/ "):
		errs.Add("project_id", "must be a project ID")
	}
	switch {
	case c.Topic == "":
		errs.Add("topic", "is required")
	case !topicID.MatchString(c.Topic) || strings.HasPrefix(strings.ToLower(c.Topic), reservedPrefix):
		errs.Add("topic", "must be a topic ID: 3 to 255 letters, digits or -._~%+, starting with a letter, not with goog")
	}
	errs.Merge("custom_attributes", validateAttributes(c.CustomAttributes))
	if c.Endpoint != "" {
		errs.Merge("endpoint", shared.ValidateBrokers([]string{c.Endpoint}))
	}
	if c.EmulatorHost != "" {
		errs.Merge("emulator_host", shared.ValidateBrokers([]string{c.EmulatorHost}))
		if c.Endpoint != "" {
			errs.Add("emulator_host", "cannot be combined with endpoint")
		}
		if c.Credentials != "" {
			errs.Add("emulator_host", "cannot be combined with credentials")
		}
	}
	if c.Credentials != "" {
		data, typ, err := parseCredentials(c.Credentials)
		if err != nil {
			errs.Add("credentials", err.Error())
		}
		c.credentialsJSON, c.credentialsType = data, typ
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateAttributes(attrs map[string]string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if len(attrs) > maxAttributes {
		errs.Add("", fmt.Sprintf("at most %d attributes", maxAttributes))
	}
	for _, key := range shared.SortMapKeys(attrs) {
		switch {
		case key == "":
			errs.Add("", "attribute names must not be empty")
		case len(key) > maxAttributeKeyBytes:
			errs.Add(key, fmt.Sprintf("name exceeds %d bytes", maxAttributeKeyBytes))
		case strings.HasPrefix(strings.ToLower(key), reservedPrefix):
			errs.Add(key, "names starting with goog are reserved")
		}
		if len(attrs[key]) > maxAttributeValBytes {
			errs.Add(key, fmt.Sprintf("value exceeds %d bytes", maxAttributeValBytes))
		}
	}
	return errs
}

// parseCredentials accepts a credentials JSON document, raw or base64-encoded.
// Errors never include the value.
func parseCredentials(value string) (data []byte, typ option.CredentialsType, err error) {
	invalid := errors.New("must be a credentials JSON document, raw or base64-encoded")
	data = []byte(strings.TrimSpace(value))
	if len(data) > 0 && data[0] != '{' {
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(data))
		if decodeErr != nil {
			return nil, "", invalid
		}
		data = []byte(strings.TrimSpace(string(decoded)))
	}
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &header) != nil {
		return nil, "", invalid
	}
	typ, ok := credentialTypes[header.Type]
	if !ok {
		return nil, "", errors.New("type must be service_account, authorized_user, impersonated_service_account or external_account")
	}
	return data, typ, nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	return &driver{cfg: cfg}, nil
}

func (d *driver) clientOptions() []option.ClientOption {
	if d.cfg.EmulatorHost != "" {
		return []option.ClientOption{
			option.WithEndpoint(d.cfg.EmulatorHost),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
			option.WithoutAuthentication(),
			option.WithTelemetryDisabled(),
		}
	}
	var opts []option.ClientOption
	if d.cfg.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(d.cfg.Endpoint))
	}
	if d.cfg.credentialsJSON != nil {
		opts = append(opts, option.WithAuthCredentialsJSON(d.cfg.credentialsType, d.cfg.credentialsJSON))
	}
	return opts
}

func (d *driver) Name() string { return name }

// Init creates the client and the topic publisher. It fails when the
// credentials cannot be loaded; the cause is not returned, as it may quote
// the credentials.
func (d *driver) Init(ctx context.Context) error {
	client, err := pubsub.NewClient(ctx, d.cfg.ProjectID, d.clientOptions()...)
	if err != nil {
		reason := "application default credentials not found"
		switch {
		case d.cfg.EmulatorHost != "":
			reason = "cannot create client"
		case d.cfg.credentialsJSON != nil:
			reason = "cannot load credentials"
		}
		return fmt.Errorf("%s client: %w: %s", name, output.ErrMisconfigured, reason)
	}
	d.client = client
	d.publisher = client.Publisher(d.cfg.Topic)
	return nil
}

func (d *driver) message(evt *event.Event) (*pubsub.Message, error) {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil, shared.WrapDeliveryError(name, "marshal", err)
	}
	return &pubsub.Message{Data: data, Attributes: d.cfg.CustomAttributes}, nil
}

// Send publishes one event and waits for the server acknowledgement.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

// SendBatch publishes every event and waits for each result. Any failure
// fails the batch.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.publisher == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	results := make([]*pubsub.PublishResult, 0, len(events))
	for _, evt := range events {
		msg, err := d.message(evt)
		if err != nil {
			return err
		}
		results = append(results, d.publisher.Publish(ctx, msg))
	}
	var first error
	failed := 0
	for _, res := range results {
		if _, err := res.Get(ctx); err != nil {
			failed++
			if first == nil {
				first = safeError("publish", err)
			}
		}
	}
	if first == nil {
		return nil
	}
	if len(results) == 1 {
		return first
	}
	return fmt.Errorf("%d of %d messages failed: %w", failed, len(results), first)
}

// HealthCheck reads the topic metadata. A missing topic, a rejected
// credential or an invalid name is a misconfiguration. PermissionDenied is
// transient: the Pub/Sub Publisher role grants pubsub.topics.publish but not
// pubsub.topics.get.
func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	_, err := d.client.TopicAdminClient.GetTopic(ctx, &pubsubpb.GetTopicRequest{Topic: d.publisher.String()})
	if err == nil {
		return nil
	}
	safe := safeError("topic check", err)
	switch status.Code(err) {
	case codes.NotFound, codes.Unauthenticated, codes.InvalidArgument:
		return fmt.Errorf("%w: %w", output.ErrMisconfigured, safe)
	default:
		return safe
	}
}

// safeError describes a failure by its gRPC code or class, never by its
// message, which can quote credentials or token responses.
func safeError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return shared.WrapDeliveryError(name, operation, err)
	}
	if errors.Is(err, pubsub.ErrOversizedMessage) {
		return fmt.Errorf("%s %s: message too large", name, operation)
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Canceled:
			return shared.WrapDeliveryError(name, operation, context.Canceled)
		case codes.DeadlineExceeded:
			return shared.WrapDeliveryError(name, operation, context.DeadlineExceeded)
		default:
			return fmt.Errorf("%s %s: %s", name, operation, st.Code())
		}
	}
	return shared.WrapDeliveryError(name, operation, err)
}

// Close flushes buffered messages for at most closeTimeout, then closes the
// client. Messages still pending fail when the connection closes.
func (d *driver) Close() error {
	if d.client == nil {
		return nil
	}
	stopped := make(chan struct{})
	go func() {
		d.publisher.Stop()
		close(stopped)
	}()
	var flushErr error
	timer := time.NewTimer(closeTimeout)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		flushErr = fmt.Errorf("%s: flush did not complete within %s", name, closeTimeout)
	}
	client := d.client
	d.client = nil
	if err := client.Close(); err != nil && flushErr == nil {
		return shared.WrapDeliveryError(name, "close", err)
	}
	return flushErr
}

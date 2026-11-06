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

	pubsub "cloud.google.com/go/pubsub/v2/apiv1"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "gcppubsub"

	opClient     = "client"
	opPublish    = "publish"
	opTopicCheck = "topic check"

	// Resource limits: https://cloud.google.com/pubsub/quotas#resource_limits
	maxAttributes        = 100
	maxAttributeKeyBytes = 256
	maxAttributeValBytes = 1024
	maxRequestMessages   = 1000
	maxRequestBytes      = 10_000_000
	reservedPrefix       = "goog"

	// requestTimeout bounds one RPC, like the request timeout of the AWS and SMTP outputs.
	requestTimeout = 30 * time.Second
)

// Field numbers of PublishRequest, which the request size counts.
var (
	publishTopicField    = fieldNumber("topic")
	publishMessagesField = fieldNumber("messages")
)

func fieldNumber(field protoreflect.Name) protowire.Number {
	return (&pubsubpb.PublishRequest{}).ProtoReflect().Descriptor().Fields().ByName(field).Number()
}

// Topic IDs: https://cloud.google.com/pubsub/docs/pubsub-basics#resource_names
var topicID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._~%+-]{2,254}$`)

// credentialTypes are the Google credential JSON types the output loads.
var credentialTypes = map[string]option.CredentialsType{
	string(option.ServiceAccount):             option.ServiceAccount,
	string(option.AuthorizedUser):             option.AuthorizedUser,
	string(option.ImpersonatedServiceAccount): option.ImpersonatedServiceAccount,
	string(option.ExternalAccount):            option.ExternalAccount,
}

// retriablePublishCodes are the codes the generated TopicAdminClient retries for Publish (topic_admin_client.go).
var retriablePublishCodes = map[codes.Code]bool{
	codes.Aborted: true, codes.Canceled: true, codes.Internal: true, codes.ResourceExhausted: true,
	codes.Unknown: true, codes.Unavailable: true, codes.DeadlineExceeded: true,
}

// misconfiguredProbeCodes refuse the configuration; PermissionDenied stays transient because
// the Publisher role grants pubsub.topics.publish but not pubsub.topics.get.
var misconfiguredProbeCodes = map[codes.Code]bool{
	codes.NotFound: true, codes.Unauthenticated: true, codes.InvalidArgument: true,
}

// noRetry leaves retries to the pipeline.
var noRetry = gax.WithRetry(func() gax.Retryer { return nil })

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
	client *pubsub.TopicAdminClient
	topic  string
	cfg    config
	// timeout bounds an RPC whose context has no deadline.
	timeout time.Duration
}

// callOptions leave retries to the pipeline and bound each RPC: the generated client sets no deadline.
func (d *driver) callOptions() []gax.CallOption {
	return []gax.CallOption{noRetry, gax.WithTimeout(d.timeout)}
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

// parseCredentials accepts raw or base64 JSON; errors never include the value.
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
	return &driver{cfg: cfg, topic: "projects/" + cfg.ProjectID + "/topics/" + cfg.Topic, timeout: requestTimeout}, nil
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

// Init drops the credential load cause, which may quote the credentials.
func (d *driver) Init(ctx context.Context) error {
	client, err := pubsub.NewTopicAdminClient(ctx, d.clientOptions()...)
	if err != nil {
		code := "application default credentials not found"
		switch {
		case d.cfg.EmulatorHost != "":
			code = "cannot create client"
		case d.cfg.credentialsJSON != nil:
			code = "cannot load credentials"
		}
		return &shared.DeliveryError{Output: name, Operation: opClient, Code: code, Misconfigured: true}
	}
	d.client = client
	return nil
}

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

// SendBatch publishes in requests within the Pub/Sub limits; each request succeeds or fails as a whole.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	messages := make([]*pubsubpb.PubsubMessage, 0, len(events))
	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpMarshal, err)
		}
		messages = append(messages, &pubsubpb.PubsubMessage{Data: data, Attributes: d.cfg.CustomAttributes})
	}
	chunks := splitRequests(d.topic, messages)
	var failures []*shared.DeliveryError
	failed := 0
	for _, chunk := range chunks {
		req := &pubsubpb.PublishRequest{Topic: d.topic, Messages: chunk}
		if _, err := d.client.Publish(ctx, req, d.callOptions()...); err != nil {
			failures = append(failures, newDeliveryError(opPublish, err))
			failed += len(chunk)
		}
	}
	switch {
	case len(failures) == 0:
		return nil
	case len(chunks) == 1:
		return failures[0]
	}
	permanent := true
	for _, failure := range failures {
		permanent = permanent && output.IsPermanent(failure)
	}
	return &shared.DeliveryError{
		Cause: ctx.Err(), Output: name, Operation: opPublish, Permanent: permanent,
		Code: fmt.Sprintf("%d of %d messages failed, first: %s", failed, len(messages), failures[0].Reason()),
	}
}

// splitRequests groups messages in order into requests of at most maxRequestMessages and maxRequestBytes,
// counting the encoded request: the topic field and each message with its field tag and length.
// A message larger than the limit goes alone and the service rejects it.
func splitRequests(topic string, messages []*pubsubpb.PubsubMessage) [][]*pubsubpb.PubsubMessage {
	var chunks [][]*pubsubpb.PubsubMessage
	current := make([]*pubsubpb.PubsubMessage, 0, min(len(messages), maxRequestMessages))
	base := protowire.SizeTag(publishTopicField) + protowire.SizeBytes(len(topic))
	size := base
	for _, msg := range messages {
		msgSize := protowire.SizeTag(publishMessagesField) + protowire.SizeBytes(proto.Size(msg))
		if len(current) > 0 && (len(current) == maxRequestMessages || size+msgSize > maxRequestBytes) {
			chunks = append(chunks, current)
			current, size = make([]*pubsubpb.PubsubMessage, 0, maxRequestMessages), base
		}
		current = append(current, msg)
		size += msgSize
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	_, err := d.client.GetTopic(ctx, &pubsubpb.GetTopicRequest{Topic: d.topic}, d.callOptions()...)
	if err == nil {
		return nil
	}
	diagnostic := newDeliveryError(opTopicCheck, err)
	st, _ := status.FromError(err)
	diagnostic.Misconfigured = misconfiguredProbeCodes[st.Code()]
	return diagnostic
}

// newDeliveryError names a failure by its gRPC code; the status message can quote credentials or token responses.
// A failed TLS handshake is Unavailable and retried: grpc-go reports an untrusted certificate and a connection
// reset during the handshake with the same status and no typed cause.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
	st, ok := status.FromError(err)
	switch {
	case !ok:
		return shared.NewDeliveryError(name, operation, err)
	case st.Code() == codes.Canceled:
		return shared.NewDeliveryError(name, operation, context.Canceled)
	case st.Code() == codes.DeadlineExceeded:
		return shared.NewDeliveryError(name, operation, context.DeadlineExceeded)
	default:
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: operation, Code: st.Code().String(),
			Permanent: !retriablePublishCodes[st.Code()],
		}
	}
}

func (d *driver) Close() error {
	if d.client == nil {
		return nil
	}
	client := d.client
	d.client = nil
	return shared.WrapDeliveryError(name, shared.OpClose, client.Close())
}

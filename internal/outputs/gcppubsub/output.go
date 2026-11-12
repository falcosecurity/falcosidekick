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
	Attributes   map[string]string `mapstructure:"attributes"`
	ProjectID    string            `mapstructure:"project_id"`
	Topic        string            `mapstructure:"topic"`
	Credentials  string            `mapstructure:"credentials"`
	Endpoint     string            `mapstructure:"endpoint"`
	EmulatorHost string            `mapstructure:"emulator_host"`
	// MessageAttributes is nil when the key is absent, which means defaultMessageAttributes.
	MessageAttributes []string `mapstructure:"message_attributes"`
	credentialsType   option.CredentialsType
	credentialsJSON   []byte
	Runtime           output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Google Cloud Pub/Sub output for the catalog.
var OutputType = output.Type{
	New:           createOutput,
	CheckAPIWrite: checkAPIWrite,
	Name:          name,
	Category:      output.CategoryQueue,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{
				Name: "project_id", Type: "string", Required: true, Label: "Project ID",
				Description: "ID of the Google Cloud project that owns the topic, such as `my-project`, not its name or number path.",
			},
			{
				Name: "topic", Type: "string", Required: true, Label: "Topic ID",
				Description: "ID of the topic within the project, not its full `projects/.../topics/...` name: 3 to 255 characters starting with a letter, not with `goog`.",
			},
			{
				Name: "credentials", Type: "string", Secret: true, Label: "Credentials JSON (default: Application Default Credentials)",
				Description: "Google credentials JSON document of type `service_account`, `authorized_user`, `impersonated_service_account` or `external_account`. " +
					"Empty uses Application Default Credentials.",
			},
			{
				Name: "attributes", Type: "map", Label: "Static attributes",
				Description: "Attributes set on every message, by name: names up to 256 bytes not starting with `goog`, values up to 1024 bytes. " +
					"With `message_attributes`, at most 100 per message.",
			},
			{
				Name: "message_attributes", Type: "string[]", Default: defaultMessageAttributes,
				Label: "Message attributes: priority, rule, source, tags, hostname or output field names",
				Description: "Event values sent as attributes, which subscription filters can select on: `priority`, `rule`, `source`, `tags`, " +
					"`hostname` or output field names. Missing, empty, non-text, non-number or over 1024-byte values are left out.",
			},
			{
				Name: "endpoint", Type: "string", Label: "gRPC endpoint host:port (TLS)",
				Description: "Pub/Sub service address as `host:port` without a scheme, such as a regional or private endpoint, reached over TLS. Empty uses the global Google endpoint.",
			},
			{
				Name: "emulator_host", Type: "string", Label: "Emulator host:port (plaintext, no authentication)",
				Description: "Address of a Pub/Sub emulator as `host:port`, reached in plaintext without authentication; cannot be combined with the endpoint or credentials.",
			},
		}, shared.BatchRuntimeConfigSchemaFields()...),
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
	errs.Merge("attributes", validateAttributes(c.Attributes))
	if c.MessageAttributes == nil {
		c.MessageAttributes = defaultMessageAttributes
	}
	errs.Merge("message_attributes", validateMessageAttributes(c.MessageAttributes, c.Attributes))
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
		if err := checkAttributeName(key); err != "" {
			errs.Add(key, err)
		}
		if len(attrs[key]) > maxAttributeValBytes {
			errs.Add(key, fmt.Sprintf("value exceeds %d bytes", maxAttributeValBytes))
		}
	}
	return errs
}

// checkAttributeName returns why Pub/Sub refuses name, or "".
func checkAttributeName(name string) string {
	switch {
	case name == "":
		return "attribute names must not be empty"
	case len(name) > maxAttributeKeyBytes:
		return fmt.Sprintf("name exceeds %d bytes", maxAttributeKeyBytes)
	case strings.HasPrefix(strings.ToLower(name), reservedPrefix):
		return "names starting with goog are reserved"
	}
	return ""
}

// parseCredentials accepts a JSON document only; errors never include the value.
func parseCredentials(value string) (data []byte, typ option.CredentialsType, err error) {
	invalid := errors.New("must be a credentials JSON document")
	data = []byte(strings.TrimSpace(value))
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

// checkAPIWrite refuses inline credentials with a credential_source: the Google library reads the file, URL, metadata server or
// certificate it names and sends the result to the document's token_url, so an API write could read local resources out.
func checkAPIWrite(patch map[string]any) error {
	for key, value := range patch {
		text, ok := value.(string)
		if !strings.EqualFold(key, "credentials") || !ok || text == "" {
			continue
		}
		data, _, err := parseCredentials(text)
		if err != nil {
			return nil // the decoder reports it
		}
		var document any
		if json.Unmarshal(data, &document) == nil && hasCredentialSource(document) {
			return errors.New("credentials: a credential_source is accepted only from output files or credentials_file")
		}
	}
	return nil
}

func hasCredentialSource(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if strings.EqualFold(key, "credential_source") || hasCredentialSource(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if hasCredentialSource(child) {
				return true
			}
		}
	}
	return false
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", name, errs)
	}
	return &driver{cfg: cfg, topic: "projects/" + cfg.ProjectID + "/topics/" + cfg.Topic, timeout: requestTimeout}, nil
}

// clientOptions caps the gRPC reconnection backoff for the emulator and for Google Cloud alike.
func (d *driver) clientOptions() []option.ClientOption {
	reconnect := option.WithGRPCDialOption(shared.GRPCReconnect)
	if d.cfg.EmulatorHost != "" {
		return []option.ClientOption{
			option.WithEndpoint(d.cfg.EmulatorHost),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
			option.WithoutAuthentication(),
			option.WithTelemetryDisabled(),
			reconnect,
		}
	}
	opts := []option.ClientOption{reconnect}
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
		messages = append(messages, &pubsubpb.PubsubMessage{Data: data, Attributes: messageAttributes(evt, d.cfg.Attributes, d.cfg.MessageAttributes)})
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
	return shared.JoinDeliveryErrors(ctx, name, opPublish, failures, failed, len(messages), "messages")
}

// splitRequests groups messages in order into requests within maxRequestMessages and maxRequestBytes, counting the encoded request:
// the topic field and each message with its field tag and length. A message over the limit goes alone, for the service to reject.
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

// newDeliveryError names a failure by its gRPC code; the status message can quote credentials or token responses. A failed TLS handshake
// is Unavailable and retried: grpc-go reports an untrusted certificate and a reset during the handshake alike, with no typed cause.
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

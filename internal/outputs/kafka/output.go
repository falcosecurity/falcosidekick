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

package kafka

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

type config struct {
	Auth            kafkaAuth                `mapstructure:"auth"`
	Topic           string                   `mapstructure:"topic"`
	TopicField      string                   `mapstructure:"topic_field"`
	MessageKey      string                   `mapstructure:"message_key"`
	MessageKeyField string                   `mapstructure:"message_key_field"`
	TLS             shared.OptionalTLSConfig `mapstructure:"tls"`
	Producer        kafkaProducer            `mapstructure:"producer"`
	Brokers         []string                 `mapstructure:"brokers"`
	Runtime         output.RuntimeConfig     `mapstructure:"runtime"`
}

type kafkaAuth struct {
	SASL     string `mapstructure:"sasl"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type kafkaProducer struct {
	Compression     string        `mapstructure:"compression"`
	RequiredACKs    string        `mapstructure:"required_acks"`
	ClientID        string        `mapstructure:"client_id"`
	DeliveryTimeout time.Duration `mapstructure:"delivery_timeout"`
	TopicCreation   bool          `mapstructure:"auto_create_topic"`
}

// OutputType describes the Kafka output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryQueue,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{
				Name: "brokers", Type: "string[]", Required: true, Label: "Broker addresses",
				Description: "Seed brokers as `host:port`, without scheme or path. The client discovers the rest of the cluster from them.",
			},
			{
				Name: "topic", Type: "string", Required: true, Label: "Default topic",
				Description: "Topic for events without a `topic_field` value. Startup checks that it exists, not that the client may write to it.",
			},
			{
				Name: "topic_field", Type: "string", Label: "Topic from event field (overrides default)",
				Description: "Output field, such as `k8s.ns.name`, whose string value names the topic. " +
					"Events without a non-empty string value use `topic`. These topics are not checked at startup.",
			},
			{
				Name: "message_key", Type: "string", Label: "Static message key (for partition affinity)",
				Description: "Record key used when `message_key_field` gives no value; records with the same key go to the same partition. " +
					"Empty sends records without a key, spread across partitions.",
			},
			{
				Name: "message_key_field", Type: "string", Label: "Message key from event field",
				Description: "Output field whose non-empty string value is the record key. Otherwise `message_key` applies.",
			},
			{
				Name: "auth.sasl", Type: "enum", Values: []string{saslPlain, saslSCRAMSHA256, saslSCRAMSHA512}, Label: "SASL Mechanism",
				Description: "SASL mechanism for broker authentication, spelled as Kafka does: `PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`. " +
					"Empty disables SASL; any mechanism requires username and password.",
			},
			{
				Name: "auth.username", Type: "string", Label: "SASL Username",
				Description: "User for SASL authentication. Requires `auth.sasl`.",
			},
			{
				Name: "auth.password", Type: "string", Secret: true, Label: "SASL Password",
				Description: "Password for SASL authentication. Requires `auth.sasl`.",
			},
			{
				Name: "producer.compression", Type: "enum", Values: []string{"none", "gzip", "snappy", "lz4", "zstd"}, Label: "Compression",
				Description: "Codec for record batches sent to the brokers. Empty keeps the client default: `snappy`, " +
					"or no compression for brokers that do not support it.",
			},
			{
				Name: "producer.required_acks", Type: "enum", Values: []string{"all", "one", "none"}, Default: "all", Label: "Required ACKs",
				Description: "Acknowledgement the brokers give before a record counts as written: all in-sync replicas, the leader, or none. " +
					"Idempotent writes are enabled only with `all`.",
			},
			{
				Name: "producer.client_id", Type: "string", Default: defaultClientID, Label: "Client ID",
				Description: "Client ID sent to the brokers, visible in their logs and quotas.",
			},
			{
				Name: "producer.auto_create_topic", Type: "bool", Default: false, Label: "Allow Auto Topic Creation",
				Description: "Asks the brokers to create a missing topic, if they allow it, and lets startup accept a missing default topic.",
			},
			{
				Name: "producer.delivery_timeout", Type: "string", Default: defaultDeliveryTimeout.String(), Label: "Delivery Timeout",
				Description: "Go duration, such as `10s`, bounding each delivery attempt, client retries included, and the flush on shutdown. " +
					"At least `1s`.",
			},
		}, append(shared.OptionalTLSSchemaFields(), shared.BatchRuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	client *kgo.Client
	// purged holds when each recreated topic was last purged, guarded by purgeMu.
	purged  map[string]time.Time
	opts    []kgo.Opt
	cfg     config
	purgeMu sync.Mutex
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var (
	validSASL         = map[string]bool{"": true, saslPlain: true, saslSCRAMSHA256: true, saslSCRAMSHA512: true}
	validCompression  = map[string]bool{"": true, "none": true, "gzip": true, "snappy": true, "lz4": true, "zstd": true}
	validRequiredACKs = map[string]bool{"": true, "all": true, "one": true, "none": true}
)

const (
	name     = "kafka"
	opClient = "client"

	// SASL mechanism names as Kafka spells them in sasl.enabled.mechanisms.
	saslPlain       = "PLAIN"
	saslSCRAMSHA256 = "SCRAM-SHA-256"
	saslSCRAMSHA512 = "SCRAM-SHA-512"

	defaultClientID        = "falcosidekick"
	defaultDeliveryTimeout = 10 * time.Second
	// minDeliveryTimeout is the lowest record timeout franz-go accepts.
	minDeliveryTimeout = time.Second
	// codeTimeout reports an attempt that ran out of time, whatever the broker last answered.
	codeTimeout = "timeout (delivery timeout exceeded)"
)

func (a *kafkaAuth) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validSASL[a.SASL] {
		errs.Add("sasl", "must be PLAIN/SCRAM-SHA-256/SCRAM-SHA-512")
	}
	if a.SASL != "" && (a.Username == "" || a.Password == "") {
		errs.Add("username", "username and password are required when sasl is set")
	}
	if a.SASL == "" && (a.Username != "" || a.Password != "") {
		errs.Add("sasl", "is required when username or password is set")
	}
	return errs
}

func (p *kafkaProducer) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validCompression[p.Compression] {
		errs.Add("compression", "must be none/gzip/snappy/lz4/zstd")
	}
	if !validRequiredACKs[p.RequiredACKs] {
		errs.Add("required_acks", "must be all/one/none")
	}
	if p.DeliveryTimeout < minDeliveryTimeout {
		errs.Add("delivery_timeout", "must be at least "+minDeliveryTimeout.String())
	}
	return errs
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("tls", c.TLS.Validate())
	errs.Merge("brokers", shared.ValidateBrokers(c.Brokers))
	if c.Topic == "" {
		errs.Add("topic", "is required")
	}
	errs.Merge("auth", c.Auth.validate())
	errs.Merge("producer", c.Producer.validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if !hasKey(raw, "producer", "delivery_timeout") {
		cfg.Producer.DeliveryTimeout = defaultDeliveryTimeout
	}
	if cfg.Producer.ClientID == "" {
		cfg.Producer.ClientID = defaultClientID
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", name, errs)
	}

	opts, err := buildClientOpts(&cfg, shared.ResolveLogger(deps.Logger, name))
	if err != nil {
		return nil, err
	}

	return &driver{
		cfg:    cfg,
		opts:   opts,
		purged: make(map[string]time.Time),
	}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(_ context.Context) error {
	client, err := kgo.NewClient(d.opts...)
	if err != nil {
		return fmt.Errorf("%s client: %w", name, err)
	}
	d.client = client
	return nil
}

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	record, err := d.buildRecord(evt)
	if err != nil {
		return err
	}
	return d.produce(ctx, record)
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	records := make([]*kgo.Record, 0, len(events))
	for _, event := range events {
		record, err := d.buildRecord(event)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	return d.produce(ctx, records...)
}

// produce bounds one attempt by the delivery timeout, or by ctx when it ends earlier, waiting for the
// records' results rather than for the client: franz-go fails a buffered record whose context ended
// only on its next produce attempt or metadata update, a cycle that outlives the deadline with the
// broker gone. It never sends a batch whose context ended; a batch in flight at the deadline may be duplicated.
func (d *driver) produce(ctx context.Context, records ...*kgo.Record) error {
	attempt, cancel := context.WithTimeout(ctx, d.cfg.Producer.DeliveryTimeout)
	defer cancel()
	results := make(chan kgo.ProduceResult, len(records))
	for _, record := range records {
		d.client.Produce(attempt, record, func(r *kgo.Record, err error) { results <- kgo.ProduceResult{Record: r, Err: err} })
	}
	collected := make(kgo.ProduceResults, 0, len(records))
	for len(collected) < len(records) {
		select {
		case result := <-results:
			collected = append(collected, result)
		case <-attempt.Done():
			// Count what arrived meanwhile; the rest is reported timed out and left to the client.
			for len(collected) < len(records) {
				select {
				case result := <-results:
					collected = append(collected, result)
				default:
					return d.produced(ctx, collected, len(records)-len(collected), timedOut(ctx, attempt))
				}
			}
		}
	}
	return d.produced(ctx, collected, 0, nil)
}

// timedOut is the retryable failure of the records pending when attempt ended, by the delivery timeout or ctx.
func timedOut(ctx, attempt context.Context) *shared.DeliveryError {
	if ctx.Err() != nil {
		return shared.NewDeliveryError(name, shared.OpSend, ctx.Err())
	}
	return &shared.DeliveryError{Cause: attempt.Err(), Output: name, Operation: shared.OpSend, Code: codeTimeout}
}

// produced reports the failed and the pending records; a batch is permanent only when every failed record is.
func (d *driver) produced(ctx context.Context, results kgo.ProduceResults, pending int, timeout *shared.DeliveryError) error {
	var failures []*shared.DeliveryError
	for _, result := range results {
		d.forgetRecreatedTopic(result.Record, result.Err)
		if result.Err != nil {
			failures = append(failures, newDeliveryError(shared.OpSend, result.Err))
		}
	}
	failed := len(failures)
	if pending > 0 {
		failures = append(failures, timeout)
		failed += pending
	}
	return shared.JoinDeliveryErrors(ctx, name, shared.OpSend, failures, failed, len(results)+pending, "records")
}

// newDeliveryError names a protocol failure by its kerr code: franz-go appends broker text that can echo values.
// UNKNOWN_SERVER_ERROR is declared non-retriable but is a server failure.
// A record timeout is retryable and drops the last broker error it wraps; HealthCheck and the logs report that error.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
	if errors.Is(err, kgo.ErrRecordTimeout) {
		return &shared.DeliveryError{Cause: err, Output: name, Operation: operation, Code: codeTimeout}
	}
	if code, ok := errors.AsType[*kerr.Error](err); ok {
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: operation, Code: code.Message,
			Permanent: !code.Retriable && code != kerr.UnknownServerError,
		}
	}
	return shared.NewDeliveryError(name, operation, err)
}

// forgetRecreatedTopic lets the next attempt reach a deleted and recreated topic:
// franz-go otherwise keeps failing it with UNKNOWN_TOPIC_ID.
// A record produced before the last purge of its topic fails from the old topic ID and
// does not purge again: that would drop records already queued for the recreated topic.
// franz-go sets Timestamp when the record is produced.
func (d *driver) forgetRecreatedTopic(record *kgo.Record, err error) {
	if record == nil || !errors.Is(err, kerr.UnknownTopicID) {
		return
	}
	d.purgeMu.Lock()
	defer d.purgeMu.Unlock()
	if last, ok := d.purged[record.Topic]; ok && !record.Timestamp.After(last) {
		return
	}
	d.purged[record.Topic] = time.Now()
	d.client.PurgeTopicsFromProducing(record.Topic)
}

func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	err := d.describeTopic(ctx)
	if err == nil {
		return nil
	}
	diagnostic := newDeliveryError(shared.OpHealthcheck, err)
	diagnostic.Misconfigured = isMisconfiguration(err)
	return diagnostic
}

// describeTopic asks the brokers for the default topic: a missing topic, or one the client may not
// describe, fails every delivery while the brokers answer. Write permission is not checked. It returns when ctx ends: franz-go ignores ctx
// while the connection opens, and the abandoned request ends on the client's own timeouts or on Close.
func (d *driver) describeTopic(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		req := kmsg.NewPtrMetadataRequest()
		topic := kmsg.NewMetadataRequestTopic()
		topic.Topic = kmsg.StringPtr(d.cfg.Topic)
		req.Topics = append(req.Topics, topic)
		resp, err := req.RequestWith(ctx, d.client)
		if err == nil {
			for _, t := range resp.Topics {
				err = errors.Join(err, kerr.ErrorForCode(t.ErrorCode))
			}
		}
		if errors.Is(err, kerr.UnknownTopicOrPartition) && d.cfg.Producer.TopicCreation {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isMisconfiguration reports errors that no retry can fix.
func isMisconfiguration(err error) bool {
	return errors.Is(err, kerr.SaslAuthenticationFailed) ||
		errors.Is(err, kerr.UnsupportedSaslMechanism) ||
		errors.Is(err, kerr.IllegalSaslState) ||
		errors.Is(err, kerr.UnknownTopicOrPartition) ||
		errors.Is(err, kerr.TopicAuthorizationFailed) ||
		shared.IsTLSVerificationError(err)
}

// Close flushes for at most the delivery timeout; records still pending then fail and their sends return.
func (d *driver) Close() error {
	if d.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Producer.DeliveryTimeout)
	defer cancel()
	err := d.client.Flush(ctx)
	d.client.Close()
	return shared.WrapDeliveryError(name, shared.OpClose, err)
}

func hasKey(raw map[string]any, section, key string) bool {
	nested, ok := raw[section].(map[string]any)
	if !ok {
		return false
	}
	_, ok = nested[key]
	return ok
}

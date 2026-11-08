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
	"log/slog"
	"sync"
	"sync/atomic"
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
	Auth            kafkaAuth              `mapstructure:"auth"`
	Topic           string                 `mapstructure:"topic"`
	TopicField      string                 `mapstructure:"topic_field"`
	MessageKey      string                 `mapstructure:"message_key"`
	MessageKeyField string                 `mapstructure:"message_key_field"`
	TLS             shared.TLSClientConfig `mapstructure:"tls"`
	Producer        kafkaProducer          `mapstructure:"producer"`
	Brokers         []string               `mapstructure:"brokers"`
	Runtime         output.RuntimeConfig   `mapstructure:"runtime"`
	TLSEnabled      bool                   `mapstructure:"tls_enabled"`
}

type kafkaAuth struct {
	SASL     string `mapstructure:"sasl"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type kafkaProducer struct {
	Compression     string        `mapstructure:"compression"`
	Balancer        string        `mapstructure:"balancer"`
	RequiredACKs    string        `mapstructure:"required_acks"`
	ClientID        string        `mapstructure:"client_id"`
	DeliveryTimeout time.Duration `mapstructure:"delivery_timeout"`
	Async           bool          `mapstructure:"async"`
	TopicCreation   bool          `mapstructure:"auto_create_topic"`
}

// OutputType describes the Kafka output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryQueue,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "brokers", Type: "string[]", Required: true, Label: "Broker addresses"},
			{Name: "topic", Type: "string", Required: true, Label: "Default topic"},
			{Name: "topic_field", Type: "string", Label: "Topic from event field (overrides default)"},
			{Name: "message_key", Type: "string", Label: "Static message key (for partition affinity)"},
			{Name: "message_key_field", Type: "string", Label: "Message key from event field"},
			{Name: "tls_enabled", Type: "bool", Default: false, Label: "Enable TLS"},
			{Name: "auth.sasl", Type: "enum", Values: []string{"", "plain", "scram_sha256", "scram_sha512"}, Label: "SASL Mechanism"},
			{Name: "auth.username", Type: "string", Label: "SASL Username"},
			{Name: "auth.password", Type: "string", Secret: true, Label: "SASL Password"},
			{Name: "producer.compression", Type: "enum", Values: []string{"none", "gzip", "snappy", "lz4", "zstd"}, Default: "none", Label: "Compression"},
			{Name: "producer.balancer", Type: "enum", Values: []string{"", "round_robin", "least_backup", "sticky"}, Default: "", Label: "Partition Balancer"},
			{Name: "producer.required_acks", Type: "enum", Values: []string{"all", "one", "none"}, Default: "all", Label: "Required ACKs"},
			{Name: "producer.client_id", Type: "string", Label: "Client ID"},
			{Name: "producer.async", Type: "bool", Default: false, Label: "Async Produce (counted as sent once buffered; broker errors also count as failed)"},
			{Name: "producer.auto_create_topic", Type: "bool", Default: false, Label: "Allow Auto Topic Creation"},
			{Name: "producer.delivery_timeout", Type: "string", Default: defaultDeliveryTimeout.String(), Label: "Delivery Timeout"},
		}, append(shared.TLSClientSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	client      *kgo.Client
	logger      *slog.Logger
	lateFailure atomic.Pointer[func(error)]
	// purged holds when each recreated topic was last purged, guarded by purgeMu.
	purged   map[string]time.Time
	opts     []kgo.Opt
	cfg      config
	inflight sync.WaitGroup
	purgeMu  sync.Mutex
}

func (d *driver) SetLateFailureHandler(handler func(err error)) {
	d.lateFailure.Store(&handler)
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var (
	validSASL         = map[string]bool{"": true, "plain": true, "scram_sha256": true, "scram_sha512": true}
	validCompression  = map[string]bool{"": true, "none": true, "gzip": true, "snappy": true, "lz4": true, "zstd": true}
	validBalancer     = map[string]bool{"": true, "round_robin": true, "least_backup": true, "sticky": true}
	validRequiredACKs = map[string]bool{"": true, "all": true, "one": true, "none": true}
)

const (
	name           = "kafka"
	opAsyncProduce = "async produce"
	opClient       = "client"

	defaultDeliveryTimeout = 10 * time.Second
	// minDeliveryTimeout is the lowest record timeout franz-go accepts.
	minDeliveryTimeout = time.Second
)

func (a *kafkaAuth) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validSASL[a.SASL] {
		errs.Add("sasl", "must be plain/scram_sha256/scram_sha512")
	}
	if a.SASL != "" && (a.Username == "" || a.Password == "") {
		errs.Add("username", "username and password are required when sasl is set")
	}
	return errs
}

func (p *kafkaProducer) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validCompression[p.Compression] {
		errs.Add("compression", "must be none/gzip/snappy/lz4/zstd")
	}
	if !validBalancer[p.Balancer] {
		errs.Add("balancer", "must be round_robin/least_backup/sticky")
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
	if !c.TLSEnabled && c.TLS != (shared.TLSClientConfig{}) {
		errs.Add("tls", "is set but tls_enabled is false")
	}
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
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}

	logger := shared.ResolveLogger(deps.Logger, name)
	opts, err := buildClientOpts(&cfg, logger)
	if err != nil {
		return nil, err
	}

	return &driver{
		cfg:    cfg,
		opts:   opts,
		logger: logger,
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

	if d.cfg.Producer.Async {
		d.inflight.Add(1)
		d.client.Produce(ctx, record, d.asyncCallback)
		return nil
	}

	return d.produced(ctx, d.client.ProduceSync(ctx, record))
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

	if d.cfg.Producer.Async {
		d.inflight.Add(len(records))
		for _, r := range records {
			d.client.Produce(ctx, r, d.asyncCallback)
		}
		return nil
	}

	return d.produced(ctx, d.client.ProduceSync(ctx, records...))
}

// produced reports the failed records; a batch is permanent only when every failed record is.
func (d *driver) produced(ctx context.Context, results kgo.ProduceResults) error {
	var failures []*shared.DeliveryError
	for _, result := range results {
		d.forgetRecreatedTopic(result.Record, result.Err)
		if result.Err != nil {
			failures = append(failures, newDeliveryError(shared.OpSend, result.Err))
		}
	}
	return shared.JoinDeliveryErrors(ctx, name, shared.OpSend, failures, len(failures), len(results), "records")
}

// newDeliveryError names a protocol failure by its kerr code: franz-go appends broker text that can echo values.
// UNKNOWN_SERVER_ERROR is declared non-retriable but is a server failure.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
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
// write, fails every delivery while the brokers answer. It returns when ctx ends: franz-go ignores ctx
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

// Close flushes for at most the delivery timeout; records still pending fail through their callbacks.
func (d *driver) Close() error {
	if d.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Producer.DeliveryTimeout)
	defer cancel()
	err := d.client.Flush(ctx)
	d.client.Close()
	// Close fails every record still buffered, so each callback runs.
	d.inflight.Wait()
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

// asyncCallback counts a failure as late: the event was already counted as sent.
func (d *driver) asyncCallback(record *kgo.Record, err error) {
	defer d.inflight.Done()
	if err == nil {
		return
	}
	d.forgetRecreatedTopic(record, err)
	diagnostic := newDeliveryError(opAsyncProduce, err)
	d.logger.Error("async produce failed", "error", diagnostic)
	if handler := d.lateFailure.Load(); handler != nil {
		(*handler)(diagnostic)
	}
}

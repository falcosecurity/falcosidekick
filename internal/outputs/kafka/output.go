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
	"fmt"
	"log/slog"

	"github.com/twmb/franz-go/pkg/kgo"

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
	Compression   string `mapstructure:"compression"`
	Balancer      string `mapstructure:"balancer"`
	RequiredACKs  string `mapstructure:"required_acks"`
	ClientID      string `mapstructure:"client_id"`
	Async         bool   `mapstructure:"async"`
	TopicCreation bool   `mapstructure:"auto_create_topic"`
}

// OutputType describes the Kafka output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "kafka",
	Category: "queue",
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
			{Name: "producer.async", Type: "bool", Default: false, Label: "Async Produce"},
			{Name: "producer.auto_create_topic", Type: "bool", Default: false, Label: "Allow Auto Topic Creation"},
		}, append(shared.TLSClientSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	client *kgo.Client
	logger *slog.Logger
	opts   []kgo.Opt
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var (
	validSASL         = map[string]bool{"": true, "plain": true, "scram_sha256": true, "scram_sha512": true}
	validCompression  = map[string]bool{"": true, "none": true, "gzip": true, "snappy": true, "lz4": true, "zstd": true}
	validBalancer     = map[string]bool{"": true, "round_robin": true, "least_backup": true, "sticky": true}
	validRequiredACKs = map[string]bool{"": true, "all": true, "one": true, "none": true}
)

func (a *kafkaAuth) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validSASL[a.SASL] {
		errs.Add("sasl", fmt.Sprintf("must be plain/scram_sha256/scram_sha512, got %q", a.SASL))
	}
	if a.SASL != "" && (a.Username == "" || a.Password == "") {
		errs.Add("username", "username and password are required when sasl is set")
	}
	return errs
}

func (p *kafkaProducer) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !validCompression[p.Compression] {
		errs.Add("compression", fmt.Sprintf("must be none/gzip/snappy/lz4/zstd, got %q", p.Compression))
	}
	if !validBalancer[p.Balancer] {
		errs.Add("balancer", fmt.Sprintf("must be round_robin/least_backup/sticky, got %q", p.Balancer))
	}
	if !validRequiredACKs[p.RequiredACKs] {
		errs.Add("required_acks", fmt.Sprintf("must be all/one/none, got %q", p.RequiredACKs))
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
		return nil, fmt.Errorf("kafka config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("kafka: %s", errs.Error())
	}

	opts, err := buildClientOpts(&cfg)
	if err != nil {
		return nil, err
	}

	return &driver{
		cfg:    cfg,
		opts:   opts,
		logger: shared.ResolveLogger(deps.Logger, "kafka"),
	}, nil
}

func (d *driver) Name() string { return "kafka" }

// Init creates the Kafka client connection.
func (d *driver) Init(_ context.Context) error {
	client, err := kgo.NewClient(d.opts...)
	if err != nil {
		return fmt.Errorf("kafka client: %w", err)
	}
	d.client = client
	return nil
}

// Send delivers a single event to Kafka.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	if d.client == nil {
		return fmt.Errorf("kafka: %w", core.ErrNotReady)
	}
	record, err := d.buildRecord(evt)
	if err != nil {
		return err
	}

	if d.cfg.Producer.Async {
		d.client.Produce(ctx, record, d.asyncCallback)
		return nil
	}

	return d.client.ProduceSync(ctx, record).FirstErr()
}

// SendBatch delivers multiple events to Kafka.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.client == nil {
		return fmt.Errorf("kafka: %w", core.ErrNotReady)
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
		for _, r := range records {
			d.client.Produce(ctx, r, d.asyncCallback)
		}
		return nil
	}

	return d.client.ProduceSync(ctx, records...).FirstErr()
}

// HealthCheck tests the Kafka broker connection.
func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("kafka: %w", core.ErrNotReady)
	}
	return d.client.Ping(ctx)
}

// Close shuts down the Kafka producer. franz-go flushes buffered records internally.
func (d *driver) Close() error {
	if d.client != nil {
		d.client.Close()
	}
	return nil
}

// asyncCallback handles produce results for async mode.
func (d *driver) asyncCallback(_ *kgo.Record, err error) {
	if err != nil {
		d.logger.Error("async produce failed", "error", err)
	}
}

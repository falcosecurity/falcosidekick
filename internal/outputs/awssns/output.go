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

package awssns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	sharedaws "github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name                 = "awssns"
	opPublish            = "Publish"
	opGetTopicAttributes = "GetTopicAttributes"
)

type config struct {
	TopicARN         string `mapstructure:"topic_arn"`
	sharedaws.Config `mapstructure:",squash"`
	// MessageAttributes is nil when the key is absent, which means defaultMessageAttributes.
	MessageAttributes []string             `mapstructure:"message_attributes"`
	Runtime           output.RuntimeConfig `mapstructure:"runtime"`
	RawJSON           bool                 `mapstructure:"raw_json"`
}

// OutputType describes the AWS SNS output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "queue",
	Schema: output.Schema{
		Fields: append(append([]output.SchemaField{
			{Name: "topic_arn", Type: "string", Required: true, Label: "Topic ARN"},
			{Name: "raw_json", Type: "bool", Default: false, Label: "Publish the event JSON instead of the output text and attributes"},
			{Name: "message_attributes", Type: "string[]", Default: defaultMessageAttributes, Label: "Message attributes: priority, rule, source, tags, hostname or output field names (at most 10)"},
		}, sharedaws.SchemaFields()...), shared.RuntimeConfigSchemaFields()...),
	},
}

type driver struct {
	client *sns.Client
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() (topic arn.ARN, errs utils.ValidationErrors) {
	errs.Merge("", c.Config.Validate())
	var err error
	if c.TopicARN == "" {
		errs.Add("topic_arn", "is required")
	} else if topic, err = arn.Parse(c.TopicARN); err != nil || topic.Service != "sns" || topic.Resource == "" {
		errs.Add("topic_arn", "must be an SNS topic ARN (arn:aws:sns:REGION:ACCOUNT:NAME)")
	} else if strings.HasSuffix(topic.Resource, ".fifo") {
		// A FIFO topic rejects every message without a MessageGroupId.
		errs.Add("topic_arn", "FIFO topics are not supported")
	}
	if c.MessageAttributes == nil {
		c.MessageAttributes = defaultMessageAttributes
	}
	errs.Merge("", validateMessageAttributes(c.MessageAttributes))
	if len(errs) > 0 {
		return topic, errs
	}
	return topic, nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	topic, errs := cfg.validate()
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	awsCfg, err := cfg.Load(context.Background(), topic.Region)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &driver{client: sns.NewFromConfig(awsCfg), cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	input, err := d.publishInput(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}
	_, err = d.client.Publish(ctx, input)
	return d.cfg.WrapError(name, opPublish, err)
}

func (d *driver) publishInput(evt *event.Event) (*sns.PublishInput, error) {
	input := &sns.PublishInput{TopicArn: sdkaws.String(d.cfg.TopicARN)}
	if d.cfg.RawJSON {
		body, err := json.Marshal(evt)
		if err != nil {
			return nil, err
		}
		input.Message = sdkaws.String(string(body))
		return input, nil
	}
	message := evt.Output
	if message == "" {
		message = evt.Rule
	}
	input.Message = sdkaws.String(message)
	input.MessageAttributes = messageAttributes(evt, d.cfg.MessageAttributes)
	return input, nil
}

// HealthCheck sends GetTopicAttributes, which needs sns:GetTopicAttributes.
func (d *driver) HealthCheck(ctx context.Context) error {
	_, err := d.client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: sdkaws.String(d.cfg.TopicARN)})
	return d.cfg.WrapProbeError(name, opGetTopicAttributes, err)
}

func (d *driver) Close() error {
	sharedaws.CloseIdleConnections(d.client.Options().HTTPClient)
	return nil
}

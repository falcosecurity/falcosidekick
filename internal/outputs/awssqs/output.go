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

package awssqs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	sharedaws "github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "awssqs"

	// SendMessageBatch limits:
	// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessageBatch.html
	maxBatchEntries = 10
	maxBatchBytes   = 1 << 20
)

type config struct {
	QueueURL         string `mapstructure:"queue_url"`
	sharedaws.Config `mapstructure:",squash"`
	Runtime          output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the AWS SQS output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "queue",
	Schema: output.Schema{
		Fields: append(append([]output.SchemaField{
			{Name: "queue_url", Type: "string", Required: true, Label: "Queue URL"},
		}, sharedaws.SchemaFields()...), shared.RuntimeConfigSchemaFields()...),
	},
}

type driver struct {
	client *sqs.Client
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.Config.Validate())
	if c.QueueURL == "" {
		errs.Add("queue_url", "is required")
	} else if !shared.IsAbsoluteHTTPURL(c.QueueURL) {
		errs.Add("queue_url", "must be an http or https URL")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	awsCfg, err := cfg.Load(context.Background(), queueRegion(cfg.QueueURL))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &driver{client: sqs.NewFromConfig(awsCfg), cfg: cfg}, nil
}

// queueRegion returns the region in an SQS queue URL host, either
// sqs.<region>.<domain> or the legacy <region>.queue.<domain>.
func queueRegion(queueURL string) string {
	u, err := url.Parse(queueURL)
	if err != nil {
		return ""
	}
	labels := strings.Split(u.Hostname(), ".")
	switch {
	case len(labels) > 2 && labels[0] == "sqs":
		return labels[1]
	case len(labels) > 2 && labels[1] == "queue":
		return labels[0]
	}
	return ""
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

// Send sends the event JSON as one message.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, "marshal", err)
	}
	_, err = d.client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    sdkaws.String(d.cfg.QueueURL),
		MessageBody: sdkaws.String(string(body)),
	})
	return d.cfg.WrapError(name, "SendMessage", err)
}

// SendBatch sends one message per event with SendMessageBatch, split into
// requests of at most 10 entries and 1 MiB. The batch fails when any
// entry fails; a request error stops the remaining requests.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	bodies := make([]string, len(events))
	for i, evt := range events {
		body, err := json.Marshal(evt)
		if err != nil {
			return shared.WrapDeliveryError(name, "marshal", err)
		}
		bodies[i] = string(body)
	}
	var failed int
	var codes []string
	for _, chunk := range splitBatch(bodies) {
		entries := make([]sqstypes.SendMessageBatchRequestEntry, len(chunk))
		for i, body := range chunk {
			entries[i] = sqstypes.SendMessageBatchRequestEntry{
				Id:          sdkaws.String(strconv.Itoa(i)),
				MessageBody: sdkaws.String(body),
			}
		}
		out, err := d.client.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{
			QueueUrl: sdkaws.String(d.cfg.QueueURL),
			Entries:  entries,
		})
		if err != nil {
			return d.cfg.WrapError(name, "SendMessageBatch", err)
		}
		failed += len(out.Failed)
		for _, f := range out.Failed {
			if code := sdkaws.ToString(f.Code); !slices.Contains(codes, code) {
				codes = append(codes, code)
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("%s SendMessageBatch: %d/%d entries failed (%s)", name, failed, len(events), strings.Join(codes, ", "))
	}
	return nil
}

// splitBatch groups bodies in order into chunks within the
// SendMessageBatch limits. A body larger than maxBatchBytes goes alone, and
// SQS decides whether to accept it.
func splitBatch(bodies []string) [][]string {
	var chunks [][]string
	current := make([]string, 0, maxBatchEntries)
	size := 0
	for _, body := range bodies {
		if len(current) > 0 && (len(current) == maxBatchEntries || size+len(body) > maxBatchBytes) {
			chunks = append(chunks, current)
			current, size = make([]string, 0, maxBatchEntries), 0
		}
		current = append(current, body)
		size += len(body)
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

// HealthCheck reads the queue ARN with GetQueueAttributes, which needs
// sqs:GetQueueAttributes. A missing queue, rejected credentials or a denied
// request wrap output.ErrMisconfigured.
func (d *driver) HealthCheck(ctx context.Context) error {
	_, err := d.client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       sdkaws.String(d.cfg.QueueURL),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn},
	})
	return d.cfg.WrapProbeError(name, "GetQueueAttributes", err)
}

func (d *driver) Close() error { return nil }

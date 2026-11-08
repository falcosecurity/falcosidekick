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

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snsEnvelope is the notification an SQS subscriber gets without raw message delivery.
type snsEnvelope struct {
	MessageAttributes map[string]struct {
		Type  string `json:"Type"`
		Value string `json:"Value"`
	} `json:"MessageAttributes"`
	Message  string `json:"Message"`
	TopicArn string `json:"TopicArn"`
}

func (a *awsTarget) createTopic(t *testing.T, marker string) (topicARN, queueURL string) {
	t.Helper()
	client := sns.NewFromConfig(a.cfg)
	out, err := client.CreateTopic(awsContext(t), &sns.CreateTopicInput{Name: aws.String("fsk-e2e-" + marker)})
	require.NoError(t, err)
	topicARN = aws.ToString(out.TopicArn)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = client.DeleteTopic(ctx, &sns.DeleteTopicInput{TopicArn: aws.String(topicARN)})
	})
	queueURL, queueARN := a.createQueue(t, marker)
	_, err = client.Subscribe(awsContext(t), &sns.SubscribeInput{
		TopicArn: aws.String(topicARN), Protocol: aws.String("sqs"), Endpoint: aws.String(queueARN),
	})
	require.NoError(t, err)
	return topicARN, queueURL
}

func (a *awsTarget) receiveNotification(t *testing.T, queueURL string) snsEnvelope {
	t.Helper()
	bodies := a.receiveMessages(t, queueURL, 1)
	require.Len(t, bodies, 1)
	var env snsEnvelope
	require.NoError(t, json.Unmarshal([]byte(bodies[0]), &env), bodies[0])
	return env
}

func TestAWSSNSPublishesTextWithAttributes(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	topicARN, queueURL := target.createTopic(t, marker)
	sk := startSidekick(t, target.output("awssns", fmt.Sprintf("topic_arn: %q\nformat: text\n", topicARN)+
		"message_attributes: [priority, rule, source, tags, hostname, e2e.marker, proc.name]\n"))

	sk.postEvent(t, marker)
	env := target.receiveNotification(t, queueURL)
	assert.Equal(t, topicARN, env.TopicArn)
	assert.Equal(t, "e2e event "+marker, env.Message)
	attrs := map[string]string{}
	for name, attr := range env.MessageAttributes {
		attrs[name] = attr.Type + ":" + attr.Value
	}
	assert.Equal(t, map[string]string{
		"priority":   "String:Warning",
		"rule":       "String:E2E " + marker,
		"source":     "String:syscall",
		"tags":       "String:e2e",
		"hostname":   "String:e2e-host",
		"e2e.marker": "String:" + marker,
		"proc.name":  "String:e2e",
	}, attrs)
	st := sk.waitStatus(t, "awssns", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Equal(t, "ok", st.Status)
	target.requireSecretAbsent(t, sk, "awssns")
}

// The event JSON is the default body, with the default message attributes.
func TestAWSSNSPublishesJSONByDefault(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	topicARN, queueURL := target.createTopic(t, marker)
	sk := startSidekick(t, target.output("awssns", fmt.Sprintf("topic_arn: %q\n", topicARN)))

	sk.postEvent(t, marker)
	env := target.receiveNotification(t, queueURL)
	assertAWSEvent(t, env.Message, marker)
	attrs := map[string]string{}
	for name, attr := range env.MessageAttributes {
		attrs[name] = attr.Type + ":" + attr.Value
	}
	assert.Equal(t, map[string]string{
		"priority": "String:Warning",
		"rule":     "String:E2E " + marker,
		"source":   "String:syscall",
		"tags":     "String:e2e",
		"hostname": "String:e2e-host",
	}, attrs)
	sk.waitStatus(t, "awssns", func(st outputStatus) bool { return st.SentTotal == 1 })
}

func TestAWSSNSRefusesRawJSON(t *testing.T) {
	target := localstack(t)
	topicARN := fmt.Sprintf("arn:aws:sns:%s:000000000000:fsk-e2e-raw", awsRegion)
	logs := startSidekickFails(t, target.output("awssns", fmt.Sprintf("topic_arn: %q\nraw_json: true\n", topicARN)))
	assert.Contains(t, logs, "unknown keys: raw_json")
}

func TestAWSSNSMissingTopicFailsStartup(t *testing.T) {
	target := localstack(t)
	topicARN := fmt.Sprintf("arn:aws:sns:%s:000000000000:fsk-e2e-absent-%s", awsRegion, newMarker(t))
	logs := startSidekickFails(t, target.output("awssns", fmt.Sprintf("topic_arn: %q\n", topicARN)))
	assert.Contains(t, logs, "health check: awssns GetTopicAttributes: HTTP 404 Not Found: NotFoundException")
	assert.NotContains(t, logs, target.secret)
}

func TestAWSSNSUnreachableStartsDegraded(t *testing.T) {
	target := localstack(t)
	target.endpoint = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	topicARN := fmt.Sprintf("arn:aws:sns:%s:000000000000:fsk-e2e-unreachable", awsRegion)
	sk := startSidekick(t, target.output("awssns", fmt.Sprintf("topic_arn: %q\n", topicARN)))
	st := sk.status(t, "awssns")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "connection refused")
	target.requireSecretAbsent(t, sk, "awssns")
}

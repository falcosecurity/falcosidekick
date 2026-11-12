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
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (a *awsTarget) createQueue(t *testing.T, marker string) (queueURL, queueARN string) {
	t.Helper()
	client := sqs.NewFromConfig(a.cfg)
	out, err := client.CreateQueue(awsContext(t), &sqs.CreateQueueInput{QueueName: aws.String("fsk-e2e-" + marker)})
	require.NoError(t, err)
	queueURL = aws.ToString(out.QueueUrl)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = client.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: aws.String(queueURL)})
	})
	attrs, err := client.GetQueueAttributes(awsContext(t), &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(queueURL),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn},
	})
	require.NoError(t, err)
	return queueURL, attrs.Attributes[string(sqstypes.QueueAttributeNameQueueArn)]
}

func (a *awsTarget) receiveMessages(t *testing.T, queueURL string, want int) []string {
	t.Helper()
	client := sqs.NewFromConfig(a.cfg)
	var bodies []string
	eventuallyf(t, func() bool {
		out, err := client.ReceiveMessage(awsContext(t), &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(queueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     1,
		})
		require.NoError(t, err)
		for _, m := range out.Messages {
			bodies = append(bodies, aws.ToString(m.Body))
			_, err := client.DeleteMessage(awsContext(t), &sqs.DeleteMessageInput{QueueUrl: aws.String(queueURL), ReceiptHandle: m.ReceiptHandle})
			require.NoError(t, err)
		}
		return len(bodies) >= want
	}, "%d messages in queue %s", want, queueURL)
	return bodies
}

func TestAWSSQSDeliversEvent(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	queueURL, _ := target.createQueue(t, marker)
	sk := startSidekick(t, target.output("awssqs", fmt.Sprintf("queue_url: %q\n", queueURL)))

	sk.postEvent(t, marker)
	bodies := target.receiveMessages(t, queueURL, 1)
	require.Len(t, bodies, 1)
	assertAWSEvent(t, bodies[0], marker)
	st := sk.waitStatus(t, "awssqs", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Equal(t, "ok", st.Status)
	target.requireSecretAbsent(t, sk, "awssqs")
}

// Twelve events in one batch take two SendMessageBatch requests.
func TestAWSSQSDeliversBatch(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	queueURL, _ := target.createQueue(t, marker)
	sk := startSidekick(t, target.output("awssqs", fmt.Sprintf("queue_url: %q\n", queueURL)+
		"runtime:\n  batching:\n    enabled: true\n    batch_size: 12\n    flush_interval: 10s\n"))

	want := map[string]bool{}
	for i := range 12 {
		m := fmt.Sprintf("%s%02d", marker, i)
		want["E2E "+m] = true
		sk.postEvent(t, m)
	}
	bodies := target.receiveMessages(t, queueURL, 12)
	require.Len(t, bodies, 12)
	for _, body := range bodies {
		var evt struct {
			Rule string `json:"rule"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &evt), body)
		assert.True(t, want[evt.Rule], evt.Rule)
		delete(want, evt.Rule)
	}
	st := sk.waitStatus(t, "awssqs", func(st outputStatus) bool { return st.SentTotal == 12 })
	assert.Zero(t, st.FailedTotal)
}

func TestAWSSQSMissingQueueStartsDegraded(t *testing.T) {
	target := localstack(t)
	queueURL := fmt.Sprintf("%s/000000000000/fsk-e2e-absent-%s", target.endpoint, newMarker(t))
	_, logs := startSidekickDegraded(t, "awssqs", target.output("awssqs", fmt.Sprintf("queue_url: %q\n", queueURL)))
	assert.Contains(t, logs, "health check failed before start: awssqs GetQueueAttributes: HTTP 400 Bad Request: QueueDoesNotExist")
	assert.NotContains(t, logs, target.secret)
}

func TestAWSSQSUnreachableStartsDegraded(t *testing.T) {
	target := localstack(t)
	target.endpoint = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	sk := startSidekick(t, target.output("awssqs", fmt.Sprintf("queue_url: %q\n", target.endpoint+"/000000000000/q")))
	st := sk.status(t, "awssqs")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "connection refused")

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st = sk.waitStatus(t, "awssqs", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "awssqs SendMessage: connection refused")
	target.requireSecretAbsent(t, sk, "awssqs")
}

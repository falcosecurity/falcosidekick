//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// envPubSubEmulator is the host:port of a Pub/Sub emulator.
	envPubSubEmulator = "FALCOSIDEKICK_E2E_PUBSUB_EMULATOR"

	pubsubProject = "fsk-e2e"
	// pubsubSentinel is a fake private key: it must never reach the logs.
	pubsubSentinel = "pubsub-s3cret-sentinel"
)

// newPubSubClient uses explicit options, not PUBSUB_EMULATOR_HOST, which falcosidekick would inherit.
func newPubSubClient(t *testing.T, host string) *pubsub.Client {
	t.Helper()
	client, err := pubsub.NewClient(context.Background(), pubsubProject,
		option.WithEndpoint(host),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithoutAuthentication(),
		option.WithTelemetryDisabled(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func createPubSubTopic(t *testing.T, client *pubsub.Client, topic string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	topicName := fmt.Sprintf("projects/%s/topics/%s", pubsubProject, topic)
	subName := fmt.Sprintf("projects/%s/subscriptions/%s-sub", pubsubProject, topic)
	_, err := client.TopicAdminClient.CreateTopic(ctx, &pubsubpb.Topic{Name: topicName})
	require.NoError(t, err)
	_, err = client.SubscriptionAdminClient.CreateSubscription(ctx, &pubsubpb.Subscription{Name: subName, Topic: topicName})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.SubscriptionAdminClient.DeleteSubscription(ctx, &pubsubpb.DeleteSubscriptionRequest{Subscription: subName})
		_ = client.TopicAdminClient.DeleteTopic(ctx, &pubsubpb.DeleteTopicRequest{Topic: topicName})
	})
	return subName
}

func receiveMarker(t *testing.T, client *pubsub.Client, sub, marker string) *pubsub.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	var (
		once  sync.Once
		found *pubsub.Message
	)
	err := client.Subscriber(sub).Receive(ctx, func(_ context.Context, m *pubsub.Message) {
		m.Ack()
		if bytes.Contains(m.Data, []byte(marker)) {
			once.Do(func() {
				found = m
				cancel()
			})
		}
	})
	require.NoError(t, err)
	require.NotNil(t, found, "no message with marker %s within %s", marker, deliverTimeout)
	return found
}

func pubsubOutput(host, topic, extra string) string {
	return fmt.Sprintf("gcppubsub:\n  project_id: %q\n  topic: %q\n  emulator_host: %q\n%s", pubsubProject, topic, host, extra)
}

func TestGCPPubSubDelivers(t *testing.T) {
	host := requireEnv(t, envPubSubEmulator)
	client := newPubSubClient(t, host)
	marker := newMarker(t)
	topic := "fsk-e2e-" + marker
	sub := createPubSubTopic(t, client, topic)

	sk := startSidekick(t, pubsubOutput(host, topic, "  custom_attributes:\n    cluster: e2e\n    team: security\n"))
	sk.postEvent(t, marker)

	msg := receiveMarker(t, client, sub, marker)
	var got map[string]any
	require.NoError(t, json.Unmarshal(msg.Data, &got))
	assert.Equal(t, "E2E "+marker, got["rule"])
	assert.Equal(t, "warning", got["priority"])
	assert.Equal(t, "e2e event "+marker, got["output"])
	fields, ok := got["output_fields"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, marker, fields["e2e.marker"])
	assert.Equal(t, map[string]string{"cluster": "e2e", "team": "security"}, msg.Attributes)

	st := sk.waitStatus(t, "gcppubsub", func(s outputStatus) bool { return s.SentTotal >= 1 })
	assert.Equal(t, 0, st.FailedTotal)
	assert.Empty(t, st.LastError)
}

func TestGCPPubSubMissingTopicFailsStartup(t *testing.T) {
	host := requireEnv(t, envPubSubEmulator)
	topic := "fsk-e2e-missing-" + newMarker(t)
	logs := startSidekickFails(t, pubsubOutput(host, topic, ""))
	assert.Contains(t, logs, "gcppubsub topic check: NotFound")
}

func TestGCPPubSubRejectedCredentialsFailStartup(t *testing.T) {
	requireEnv(t, envPubSubEmulator)
	key := fmt.Sprintf(`{"type":"service_account","project_id":"p","private_key_id":"k",`+
		`"private_key":"-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n",`+
		`"client_email":"fsk@p.iam.gserviceaccount.com","token_uri":"https://oauth2.googleapis.com/token"}`, pubsubSentinel)
	quoted, err := json.Marshal(key)
	require.NoError(t, err)
	logs := startSidekickFails(t, fmt.Sprintf("gcppubsub:\n  project_id: %q\n  topic: falco\n  credentials: %s\n", pubsubProject, quoted))
	assert.Contains(t, logs, "cannot load credentials")
	assert.NotContains(t, logs, pubsubSentinel)
}

func TestGCPPubSubUnreachableStartsDegraded(t *testing.T) {
	requireEnv(t, envPubSubEmulator)
	host := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	sk := startSidekick(t, pubsubOutput(host, "falco", ""))
	st := sk.status(t, "gcppubsub")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
	assert.Contains(t, st.LastWarning, "gcppubsub topic check")
}

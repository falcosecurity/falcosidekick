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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Only the plaintext brokers are required; other tests skip when their variables are unset.
const (
	envKafkaBrokers        = "FALCOSIDEKICK_E2E_KAFKA_BROKERS"
	envKafkaSASLBrokers    = "FALCOSIDEKICK_E2E_KAFKA_SASL_BROKERS"
	envKafkaSASLUser       = "FALCOSIDEKICK_E2E_KAFKA_SASL_USER"
	envKafkaSASLPassword   = "FALCOSIDEKICK_E2E_KAFKA_SASL_PASSWORD"
	envKafkaSASLMechanisms = "FALCOSIDEKICK_E2E_KAFKA_SASL_MECHANISMS"
	envKafkaTLSBrokers     = "FALCOSIDEKICK_E2E_KAFKA_TLS_BROKERS"
	envKafkaTLSCAFile      = "FALCOSIDEKICK_E2E_KAFKA_TLS_CA_FILE"

	// kafkaShortTimeout is the producer.delivery_timeout of failure tests.
	kafkaShortTimeout = 2 * time.Second
	// kafkaFailMargin bounds the failure counter delay beyond the delivery timeout.
	kafkaFailMargin = 3 * time.Second
	// kafkaTopicField is the event output field that carries the topic name.
	kafkaTopicField = "e2e.topic"
)

type kafkaTarget struct {
	yaml    string
	brokers []string
	opts    []kgo.Opt
}

func plaintextKafka(t *testing.T) kafkaTarget {
	t.Helper()
	brokers := splitBrokers(requireEnv(t, envKafkaBrokers))
	return kafkaTarget{brokers: brokers, opts: []kgo.Opt{kgo.SeedBrokers(brokers...)}}
}

func splitBrokers(value string) []string {
	var brokers []string
	for b := range strings.SplitSeq(value, ",") {
		if b = strings.TrimSpace(b); b != "" {
			brokers = append(brokers, b)
		}
	}
	return brokers
}

func kafkaOutput(target kafkaTarget, topic, extra string) string {
	quoted := make([]string, len(target.brokers))
	for i, b := range target.brokers {
		quoted[i] = fmt.Sprintf("%q", b)
	}
	out := fmt.Sprintf("kafka:\n  brokers: [%s]\n  topic: %q\n", strings.Join(quoted, ", "), topic)
	for line := range strings.SplitSeq(strings.TrimRight(target.yaml+extra, "\n"), "\n") {
		if line != "" {
			out += "  " + line + "\n"
		}
	}
	return out
}

func newKafkaClient(t *testing.T, target kafkaTarget, extra ...kgo.Opt) *kgo.Client {
	t.Helper()
	client, err := kgo.NewClient(append(append([]kgo.Opt{}, target.opts...), extra...)...)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	return client
}

// createTopic creates the topic explicitly because broker-side auto creation stays disabled.
func createTopic(t *testing.T, target kafkaTarget, topic string) {
	t.Helper()
	client := newKafkaClient(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()

	req := kmsg.NewPtrCreateTopicsRequest()
	req.TimeoutMillis = int32(deliverTimeout / time.Millisecond)
	rt := kmsg.NewCreateTopicsRequestTopic()
	rt.Topic, rt.NumPartitions, rt.ReplicationFactor = topic, 1, 1
	req.Topics = append(req.Topics, rt)
	resp, err := req.RequestWith(ctx, client)
	require.NoError(t, err)
	require.Len(t, resp.Topics, 1)
	require.NoError(t, kerr.ErrorForCode(resp.Topics[0].ErrorCode), "create topic %s", topic)
	t.Cleanup(func() { _ = deleteTopic(target, topic) })

	// A broker answers the creation before its metadata lists the topic (Kafka 3.9 lags more than 4.x);
	// Sidekick's startup check must see the topic, as in a real deployment where it exists beforehand.
	require.Eventually(t, func() bool {
		meta := kmsg.NewPtrMetadataRequest()
		mt := kmsg.NewMetadataRequestTopic()
		mt.Topic = kmsg.StringPtr(topic)
		meta.Topics = append(meta.Topics, mt)
		got, err := meta.RequestWith(ctx, client)
		return err == nil && len(got.Topics) == 1 && got.Topics[0].ErrorCode == 0 && len(got.Topics[0].Partitions) > 0
	}, deliverTimeout, 100*time.Millisecond, "topic %s visible in the metadata", topic)
}

func deleteTopic(target kafkaTarget, topic string) error {
	admin, err := kgo.NewClient(target.opts...)
	if err != nil {
		return err
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	del := kmsg.NewPtrDeleteTopicsRequest()
	del.TopicNames = []string{topic}
	dt := kmsg.NewDeleteTopicsRequestTopic()
	dt.Topic = kmsg.StringPtr(topic)
	del.Topics = append(del.Topics, dt)
	resp, err := del.RequestWith(ctx, admin)
	if err != nil {
		return err
	}
	for _, result := range resp.Topics {
		if err := kerr.ErrorForCode(result.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}

// A topic deleted and recreated while the output runs gets a new topic ID.
func TestKafkaRecoversRecreatedTopic(t *testing.T) {
	target := plaintextKafka(t)
	marker := newMarker(t)
	topic := kafkaTopic(marker)
	createTopic(t, target, topic)
	sk := startSidekick(t, kafkaOutput(target, topic, ""))

	postKafkaEvent(t, sk, marker+"-1", topic)
	consumeMarker(t, target, topic, marker+"-1")

	require.NoError(t, deleteTopic(target, topic))
	require.Eventually(t, func() bool {
		client := newKafkaClient(t, target)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req := kmsg.NewPtrCreateTopicsRequest()
		rt := kmsg.NewCreateTopicsRequestTopic()
		rt.Topic, rt.NumPartitions, rt.ReplicationFactor = topic, 1, 1
		req.Topics = append(req.Topics, rt)
		resp, err := req.RequestWith(ctx, client)
		return err == nil && len(resp.Topics) == 1 && resp.Topics[0].ErrorCode == 0
	}, deliverTimeout, 500*time.Millisecond, "recreate topic %s", topic)

	// Events sent while brokers still serve the old topic ID can fail; the output must then recover without a restart.
	deadline := time.Now().Add(deliverTimeout)
	for i := 2; ; i++ {
		require.True(t, time.Now().Before(deadline), "no delivery to the recreated topic within %s", deliverTimeout)
		eventMarker := fmt.Sprintf("%s-%d", marker, i)
		postKafkaEvent(t, sk, eventMarker, topic)
		st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal+st.FailedTotal == i })
		if st.LastError == "" {
			consumeMarker(t, target, topic, eventMarker)
			return
		}
		time.Sleep(time.Second)
	}
}

func consumeMarker(t *testing.T, target kafkaTarget, topic, marker string) *kgo.Record {
	t.Helper()
	client := newKafkaClient(t, target,
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	for {
		fetches := client.PollFetches(ctx)
		if ctx.Err() != nil {
			t.Fatalf("no record with marker %s in topic %s within %s", marker, topic, deliverTimeout)
		}
		for _, fe := range fetches.Errors() {
			t.Logf("fetch %s/%d: %v", fe.Topic, fe.Partition, fe.Err)
		}
		var found *kgo.Record
		fetches.EachRecord(func(r *kgo.Record) {
			if found == nil && bytes.Contains(r.Value, []byte(marker)) {
				found = r
			}
		})
		if found != nil {
			return found
		}
	}
}

func postKafkaEvent(t *testing.T, sk *sidekick, marker, topic string) {
	t.Helper()
	evt := falcoEvent(marker)
	evt["output_fields"].(map[string]any)[kafkaTopicField] = topic
	body, err := json.Marshal(evt)
	require.NoError(t, err)
	resp, err := httpDo(http.MethodPost, sk.url+"/", body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func kafkaTopic(marker string) string { return "fsk-e2e-" + marker }

func recordHeaders(r *kgo.Record) map[string]string {
	h := make(map[string]string, len(r.Headers))
	for _, header := range r.Headers {
		h[header.Key] = string(header.Value)
	}
	return h
}

func assertFalcoRecord(t *testing.T, r *kgo.Record, marker string) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal(r.Value, &got))
	assert.Equal(t, "E2E "+marker, got["rule"])
	assert.NotEmpty(t, got["uuid"])
	assert.Equal(t, marker, got["output_fields"].(map[string]any)["e2e.marker"])
	assert.Equal(t, map[string]string{
		"content-type":   "application/json",
		"falco.rule":     "E2E " + marker,
		"falco.priority": "Warning",
		"falco.source":   "syscall",
	}, recordHeaders(r))
}

func TestKafkaDeliversEvent(t *testing.T) {
	target := plaintextKafka(t)
	const staticKey = "static-key"
	cases := []struct {
		// topic maps the created topic to the configured default topic.
		topic   func(created string) string
		wantKey func(marker string) string
		name    string
		// extra is YAML under the kafka key.
		extra string
	}{
		{
			name:    "sync default topic and static key",
			topic:   func(created string) string { return created },
			extra:   "message_key: " + staticKey + "\n",
			wantKey: func(string) string { return staticKey },
		},
		{
			name:  "sync topic_field and message_key_field override defaults",
			topic: func(created string) string { return created + "-default" },
			extra: "topic_field: " + kafkaTopicField + "\n" +
				"message_key: " + staticKey + "\n" +
				"message_key_field: e2e.marker\n",
			wantKey: func(marker string) string { return marker },
		},
		{
			name:    "sync without key",
			topic:   func(created string) string { return created },
			wantKey: func(string) string { return "" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := newMarker(t)
			topic := kafkaTopic(marker)
			createTopic(t, target, topic)
			if defaultTopic := tc.topic(topic); defaultTopic != topic {
				// The probe needs the default topic; the record must still go to the event's topic.
				createTopic(t, target, defaultTopic)
			}
			sk := startSidekick(t, kafkaOutput(target, tc.topic(topic), tc.extra))

			postKafkaEvent(t, sk, marker, topic)
			record := consumeMarker(t, target, topic, marker)
			assert.Equal(t, topic, record.Topic)
			assert.Equal(t, tc.wantKey(marker), string(record.Key))
			assertFalcoRecord(t, record, marker)

			st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal == 1 })
			assert.Zero(t, st.FailedTotal)
			assert.Empty(t, st.LastError)
		})
	}
}

func TestKafkaRequiredAcks(t *testing.T) {
	target := plaintextKafka(t)
	for _, acks := range []string{"all", "one", "none"} {
		t.Run(acks, func(t *testing.T) {
			marker := newMarker(t)
			topic := kafkaTopic(marker)
			createTopic(t, target, topic)
			sk := startSidekick(t, kafkaOutput(target, topic, "producer:\n  required_acks: "+acks+"\n"))

			sk.postEvent(t, marker)
			assertFalcoRecord(t, consumeMarker(t, target, topic, marker), marker)
			st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal == 1 })
			assert.Zero(t, st.FailedTotal)
		})
	}
}

// producer.async is gone: the pipeline already queues, and a record is counted once the brokers answer.
func TestKafkaAsyncIsRefused(t *testing.T) {
	target := plaintextKafka(t)
	logs := startSidekickFails(t, kafkaOutput(target, kafkaTopic(newMarker(t)), "producer:\n  async: true\n"))
	assert.Contains(t, logs, "unknown keys: async")
}

func TestKafkaCompression(t *testing.T) {
	target := plaintextKafka(t)
	// Codec ids from the Kafka record batch attributes.
	cases := []struct {
		codec string
		id    uint8
	}{
		{codec: "", id: 2}, // unset keeps the franz-go default, snappy
		{codec: "none", id: 0},
		{codec: "gzip", id: 1},
		{codec: "snappy", id: 2},
		{codec: "lz4", id: 3},
		{codec: "zstd", id: 4},
	}
	for _, tc := range cases {
		name, extra := tc.codec, "producer:\n  compression: "+tc.codec+"\n"
		if tc.codec == "" {
			name, extra = "unset", ""
		}
		t.Run(name, func(t *testing.T) {
			marker := newMarker(t)
			topic := kafkaTopic(marker)
			createTopic(t, target, topic)
			sk := startSidekick(t, kafkaOutput(target, topic, extra))

			sk.postEvent(t, marker)
			record := consumeMarker(t, target, topic, marker)
			assertFalcoRecord(t, record, marker)
			assert.Equal(t, tc.id, record.Attrs.CompressionType(), "batch codec")
			st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal == 1 })
			assert.Zero(t, st.FailedTotal)
		})
	}
}

func TestKafkaReportsMissingTopic(t *testing.T) {
	target := plaintextKafka(t)
	t.Run("default topic starts degraded and recovers", func(t *testing.T) {
		marker := newMarker(t)
		topic := kafkaTopic(marker)
		received := make(chan struct{}, 4)
		sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			received <- struct{}{}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(sibling.Close)
		outputs := kafkaOutput(target, topic, "producer:\n  delivery_timeout: 2s\n") +
			fmt.Sprintf("webhook:\n  host: %q\n", sibling.URL)
		sk, logs := startSidekickDegraded(t, "kafka", outputs)
		assert.Contains(t, logs, "UNKNOWN_TOPIC_OR_PARTITION")

		sk.postEvent(t, marker)
		select {
		case <-received:
		case <-time.After(10 * time.Second):
			t.Fatal("the sibling did not deliver while the topic is missing")
		}

		createTopic(t, target, topic)
		eventuallyf(t, func() bool {
			sk.postEvent(t, newMarker(t))
			return sk.status(t, "kafka").SentTotal > 0
		}, "kafka did not deliver after the topic was created")
	})
	t.Run("default topic with auto creation starts", func(t *testing.T) {
		sk := startSidekick(t, kafkaOutput(target, kafkaTopic(newMarker(t)), "producer:\n  auto_create_topic: true\n"))
		assert.NotEqual(t, "misconfigured", sk.status(t, "kafka").Status)
	})
	// A topic taken from the event is not probed: the record fails within delivery_timeout.
	missingEventTopic := func(t *testing.T, marker, producer string) *sidekick {
		createTopic(t, target, kafkaTopic(marker))
		return startSidekick(t, kafkaOutput(target, kafkaTopic(marker), "topic_field: e2e.marker\nproducer:\n"+producer))
	}
	t.Run("sync", func(t *testing.T) {
		marker := newMarker(t)
		sk := missingEventTopic(t, marker, "  delivery_timeout: 2s\n")

		start := time.Now()
		sk.postEvent(t, marker)
		st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.FailedTotal == 1 })
		elapsed := time.Since(start)
		assert.Zero(t, st.SentTotal)
		t.Logf("last_error: %s", st.LastError)
		assert.NotEmpty(t, st.LastError)
		assert.Less(t, elapsed, kafkaShortTimeout+kafkaFailMargin, "delivery_timeout bounds the record")
	})
}

func TestKafkaReportsUnreachableBroker(t *testing.T) {
	unreachable := kafkaTarget{brokers: []string{fmt.Sprintf("127.0.0.1:%d", freePort(t))}}
	marker := newMarker(t)
	sk := startSidekick(t, kafkaOutput(unreachable, kafkaTopic(marker), "producer:\n  delivery_timeout: 2s\n"))
	st := sk.status(t, "kafka")
	assert.Equal(t, "degraded", st.Status, "an unreachable broker at startup is transient")
	assert.Contains(t, st.LastWarning, "health check failed before start")

	start := time.Now()
	sk.postEvent(t, marker)
	st = sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Less(t, time.Since(start), kafkaShortTimeout+kafkaFailMargin, "delivery_timeout bounds the record")
	assert.Zero(t, st.SentTotal)
	t.Logf("last_error: %s", st.LastError)
	assert.NotEmpty(t, st.LastError)

	start = time.Now()
	sk.stop(t)
	assert.Less(t, time.Since(start), kafkaShortTimeout+kafkaFailMargin, "shutdown is bounded by the flush timeout")
	assert.Equal(t, 0, sk.cmd.ProcessState.ExitCode(), "SIGTERM exits cleanly\n%s", sk.logs.String())
	assert.Contains(t, sk.logs.String(), "connection refused", "the client logs the dial cause")
}

func TestKafkaSASL(t *testing.T) {
	brokers := splitBrokers(requireEnv(t, envKafkaSASLBrokers))
	user := requireEnv(t, envKafkaSASLUser)
	password := requireEnv(t, envKafkaSASLPassword)
	mechanisms := os.Getenv(envKafkaSASLMechanisms)
	if mechanisms == "" {
		mechanisms = "PLAIN,SCRAM-SHA-256,SCRAM-SHA-512"
	}

	target := func(mechanism, pass string) kafkaTarget {
		var opt kgo.Opt
		switch mechanism {
		case "PLAIN":
			opt = kgo.SASL(plain.Auth{User: user, Pass: pass}.AsMechanism())
		case "SCRAM-SHA-256":
			opt = kgo.SASL(scram.Auth{User: user, Pass: pass}.AsSha256Mechanism())
		case "SCRAM-SHA-512":
			opt = kgo.SASL(scram.Auth{User: user, Pass: pass}.AsSha512Mechanism())
		default:
			t.Fatalf("unknown SASL mechanism %q in %s", mechanism, envKafkaSASLMechanisms)
		}
		return kafkaTarget{
			brokers: brokers,
			opts:    []kgo.Opt{kgo.SeedBrokers(brokers...), opt},
			yaml:    fmt.Sprintf("auth:\n  sasl: %s\n  username: %q\n  password: %q\n", mechanism, user, pass),
		}
	}

	for mechanism := range strings.SplitSeq(mechanisms, ",") {
		mechanism = strings.TrimSpace(mechanism)
		t.Run(mechanism, func(t *testing.T) {
			good := target(mechanism, password)
			marker := newMarker(t)
			topic := kafkaTopic(marker)
			createTopic(t, good, topic)

			t.Run("delivers", func(t *testing.T) {
				sk := startSidekick(t, kafkaOutput(good, topic, ""))
				sk.postEvent(t, marker)
				assertFalcoRecord(t, consumeMarker(t, good, topic, marker), marker)
				st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal == 1 })
				assert.Zero(t, st.FailedTotal)
			})

			t.Run("wrong password starts degraded without leaking it", func(t *testing.T) {
				wrong := "wrong-" + newMarker(t)
				_, logs := startSidekickDegraded(t, "kafka", kafkaOutput(target(mechanism, wrong), topic, "producer:\n  delivery_timeout: 2s\n"))
				assert.Contains(t, logs, "health check")
				assert.Contains(t, logs, "SASL_AUTHENTICATION_FAILED")
				assert.NotContains(t, logs, wrong)
			})
		})
	}
}

func TestKafkaTLS(t *testing.T) {
	brokers := splitBrokers(requireEnv(t, envKafkaTLSBrokers))
	caFile := requireEnv(t, envKafkaTLSCAFile)
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "no certificate in %s", caFile)

	target := func(ca string) kafkaTarget {
		return kafkaTarget{
			brokers: brokers,
			opts: []kgo.Opt{
				kgo.SeedBrokers(brokers...),
				kgo.DialTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
			},
			yaml: fmt.Sprintf("tls:\n  enabled: true\n  ca_file: %q\n", ca),
		}
	}
	good := target(caFile)
	marker := newMarker(t)
	topic := kafkaTopic(marker)
	createTopic(t, good, topic)

	t.Run("delivers with ca_file", func(t *testing.T) {
		sk := startSidekick(t, kafkaOutput(good, topic, ""))
		sk.postEvent(t, marker)
		assertFalcoRecord(t, consumeMarker(t, good, topic, marker), marker)
		st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.SentTotal == 1 })
		assert.Zero(t, st.FailedTotal)
	})

	t.Run("unknown CA starts degraded and never delivers", func(t *testing.T) {
		sk, logs := startSidekickDegraded(t, "kafka", kafkaOutput(target(writeUnknownCA(t)), topic, "producer:\n  delivery_timeout: 2s\n"))
		assert.Contains(t, logs, "kafka healthcheck: TLS certificate verification failed")
		sk.postEvent(t, newMarker(t))
		st := sk.waitStatus(t, "kafka", func(st outputStatus) bool { return st.FailedTotal == 1 })
		assert.Zero(t, st.SentTotal, "verification still refuses the connection")
	})
}

// writeUnknownCA writes a self-signed CA that signed nothing the broker presents.
func writeUnknownCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fsk-e2e-unknown-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "unknown-ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

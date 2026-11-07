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

package shared_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kmsg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws/awstest"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// permanentFailureTimeout bounds one call against a destination the driver retries on its own.
const permanentFailureTimeout = 5 * time.Second

const kafkaTopic = "falco"

type statusMatrix struct {
	permanent []int
	transient []int
}

// sharedSenderStatuses is the rule of the shared HTTP sender: a 4xx is final except the four a later request can change.
var sharedSenderStatuses = statusMatrix{
	permanent: []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound},
	transient: []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusRequestTimeout},
}

type permanentCase struct {
	// permanent and transient start a destination answering a final rejection or a transient failure.
	// A row with neither runs against the HTTP answers in statuses; a row with only transient belongs
	// to a protocol without a final rejection.
	permanent func(t *testing.T) *fakeDestination
	transient func(t *testing.T) *fakeDestination
	config    func(host string) map[string]any
	name      string
	typ       string // output type when it differs from name
	statuses  statusMatrix
}

// A rejection the protocol marks as final must be reported permanent, in one attempt; any other failure must not.
func TestEveryOutputMarksPermanentRejections(t *testing.T) {
	grpcAnswer := func(code codes.Code) func(t *testing.T) *fakeDestination {
		return func(t *testing.T) *fakeDestination { return hostileGRPCServer(t, status.Error(code, "answered")) }
	}
	pubsubAnswer := func(code codes.Code) func(t *testing.T) *fakeDestination {
		return func(t *testing.T) *fakeDestination { return hostilePubSubServer(t, status.Error(code, "answered")) }
	}
	tests := []permanentCase{
		{name: "webhook", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "slack", config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/services/T/B/X"} }},
		{name: "loki", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "elasticsearch", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "elasticsearch bulk items", typ: "elasticsearch",
			permanent: func(t *testing.T) *fakeDestination { return fakeBulk(t, http.StatusBadRequest) },
			transient: func(t *testing.T) *fakeDestination { return fakeBulk(t, http.StatusServiceUnavailable) },
			config:    func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "alertmanager", config: func(h string) map[string]any { return map[string]any{"hosts": []string{h}} }},
		{name: "teams", config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/workflows/x"} }},
		{name: "discord", config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/api/webhooks/1/t"}
		}},
		{name: "grafanaoncall", config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/integrations/v1/formatted_webhook/t/"}
		}},
		{name: "talon", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "cloudevents", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "pagerduty", config: func(h string) map[string]any { return map[string]any{"host": h, "routing_key": "rk"} }},
		{name: "opsgenie", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": "k"} }},
		{name: "datadog", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": "k"} }},
		{name: "datadog v2", typ: "datadog", config: func(h string) map[string]any {
			return map[string]any{"host": h, "api_key": "k", "app_key": "a"}
		}},
		// OTLP/HTTP retries only 429, 502, 503 and 504; every other status, 500 included, is final.
		{name: "otlp", statuses: statusMatrix{
			permanent: []int{http.StatusBadRequest, http.StatusInternalServerError},
			transient: []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
		}, config: func(h string) map[string]any {
			return map[string]any{"traces": map[string]any{"endpoint": h}}
		}},
		{name: "otlp grpc", typ: "otlp", permanent: grpcAnswer(codes.InvalidArgument), transient: grpcAnswer(codes.Unavailable),
			config: func(h string) map[string]any {
				return map[string]any{"traces": map[string]any{"endpoint": h, "protocol": "grpc"}}
			}},
		// ResourceExhausted is final unless the collector attaches RetryInfo.
		{name: "otlp grpc exhausted", typ: "otlp", permanent: grpcAnswer(codes.ResourceExhausted), transient: grpcAnswer(codes.Aborted),
			config: func(h string) map[string]any {
				return map[string]any{"traces": map[string]any{"endpoint": h, "protocol": "grpc"}}
			}},
		{name: "awss3",
			permanent: func(t *testing.T) *fakeDestination { return fakeS3(t, "InvalidRequest", http.StatusBadRequest) },
			transient: func(t *testing.T) *fakeDestination {
				return fakeS3(t, awsInternalError, http.StatusInternalServerError)
			},
			config: func(h string) map[string]any {
				return awstest.Config(h, map[string]any{"bucket": "falco", "use_path_style": true})
			}},
		{name: "awssqs",
			permanent: func(t *testing.T) *fakeDestination {
				return fakeSQS(t, "InvalidMessageContents", http.StatusBadRequest, true)
			},
			transient: func(t *testing.T) *fakeDestination {
				return fakeSQS(t, awsInternalError, http.StatusInternalServerError, false)
			},
			config: func(h string) map[string]any {
				return awstest.Config(h, map[string]any{"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q"})
			}},
		{name: "awssns",
			permanent: func(t *testing.T) *fakeDestination { return fakeSNS(t, "InvalidParameter", http.StatusBadRequest) },
			transient: func(t *testing.T) *fakeDestination {
				return fakeSNS(t, awsInternalError, http.StatusInternalServerError)
			},
			config: func(h string) map[string]any {
				return awstest.Config(h, map[string]any{"topic_arn": "arn:aws:sns:us-east-1:1:t"})
			}},
		{name: "gcppubsub", permanent: pubsubAnswer(codes.InvalidArgument), transient: pubsubAnswer(codes.Unavailable),
			config: func(h string) map[string]any {
				return map[string]any{"project_id": "p", "topic": kafkaTopic, "emulator_host": h}
			}},
		// CORRUPT_MESSAGE is retriable by protocol but the only such code the client hands back at once:
		// the others it retries itself after a metadata refresh, which its 5s minimum metadata age delays.
		{name: "kafka",
			permanent: func(t *testing.T) *fakeDestination { return fakeKafkaCluster(t, kerr.TopicAuthorizationFailed.Code) },
			transient: func(t *testing.T) *fakeDestination { return fakeKafkaCluster(t, kerr.CorruptMessage.Code) },
			config: func(h string) map[string]any {
				return map[string]any{
					"brokers": []string{h}, "topic": kafkaTopic,
					"producer": map[string]any{"required_acks": "one", "delivery_timeout": "1s"},
				}
			}},
		{name: "policyreport",
			permanent: func(t *testing.T) *fakeDestination { return fakeAPIServer(t, http.StatusForbidden) },
			transient: func(t *testing.T) *fakeDestination { return fakeAPIServer(t, http.StatusServiceUnavailable) },
			config:    func(h string) map[string]any { return map[string]any{"kubeconfig": h, "falco_namespace": "falco"} }},
		{name: "redis",
			permanent: func(t *testing.T) *fakeDestination {
				return fakeRedis(t, "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")
			},
			transient: func(t *testing.T) *fakeDestination {
				return fakeRedis(t, "-LOADING Redis is loading the dataset in memory\r\n")
			},
			config: func(h string) map[string]any { return map[string]any{"address": h} }},
		{name: "smtp",
			permanent: func(t *testing.T) *fakeDestination { return fakeSMTP(t, "550 5.1.1 no such user") },
			transient: func(t *testing.T) *fakeDestination { return fakeSMTP(t, "450 4.2.1 mailbox busy") },
			config:    func(h string) map[string]any { return hostileSMTPConfig(h, map[string]any{"auth_mechanism": "none"}) }},
		// Syslog has no reply protocol, so no answer is a final rejection; a refused connection must stay transient.
		{name: "syslog", transient: func(t *testing.T) *fakeDestination { return &fakeDestination{host: refusedAddress(t)} },
			config: hostPort},
	}
	covered := map[string]bool{"inmemory": true} // stores in process, no destination
	for _, tt := range tests {
		covered[tt.outputType()] = true
	}
	for name := range outputTypes {
		require.True(t, covered[name], "output %s has no rejection case", name)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.permanent == nil && tt.transient == nil {
				statuses := tt.statuses
				if len(statuses.permanent) == 0 {
					statuses = sharedSenderStatuses
				}
				for _, code := range statuses.permanent {
					t.Run(fmt.Sprintf("permanent %d", code), func(t *testing.T) {
						runPermanentCase(t, &tt, hostileHTTPServer(t, code, ""), true)
					})
				}
				for _, code := range statuses.transient {
					t.Run(fmt.Sprintf("transient %d", code), func(t *testing.T) {
						runPermanentCase(t, &tt, hostileHTTPServer(t, code, ""), false)
					})
				}
				return
			}
			if tt.permanent != nil {
				t.Run("permanent", func(t *testing.T) { runPermanentCase(t, &tt, tt.permanent(t), true) })
			}
			t.Run("transient", func(t *testing.T) { runPermanentCase(t, &tt, tt.transient(t), false) })
		})
	}
}

func (c *permanentCase) outputType() string {
	if c.typ != "" {
		return c.typ
	}
	return c.name
}

func runPermanentCase(t *testing.T, tt *permanentCase, dest *fakeDestination, permanent bool) {
	t.Helper()
	deps := output.Deps{Logger: slog.New(slog.DiscardHandler)}
	driver, err := outputTypes[tt.outputType()].New(tt.config(dest.host), deps)
	require.NoError(t, err)
	require.NoError(t, driver.Init(context.Background()))
	t.Cleanup(func() { _ = driver.Close() })

	before := dest.attempts.Load()
	err = withCallTimeout(func(ctx context.Context) error { return driver.Send(ctx, testutil.CreateValidEvent()) })
	require.Error(t, err, "Send")
	assert.Equal(t, permanent, output.IsPermanent(err), "Send: %v", err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded, "Send must end on the answer, not on the timeout")
	if permanent {
		assert.EqualValues(t, 1, dest.attempts.Load()-before, "a final rejection is not retried by the driver")
	}
	batch, ok := driver.(output.BatchSender)
	if !ok {
		return
	}
	err = withCallTimeout(func(ctx context.Context) error {
		return batch.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
	})
	require.Error(t, err, "SendBatch")
	assert.Equal(t, permanent, output.IsPermanent(err), "SendBatch: %v", err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded, "SendBatch must end on the answer, not on the timeout")
}

func withCallTimeout(call func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), permanentFailureTimeout)
	defer cancel()
	return call(ctx)
}

// refusedAddress returns an address nothing listens on.
func refusedAddress(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	return ln.Addr().String()
}

// fakeBulk answers a bulk request with every item at code and any other request with code itself.
func fakeBulk(t *testing.T, code int) *fakeDestination {
	t.Helper()
	return hostileHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_bulk") {
			w.WriteHeader(code)
			return
		}
		_, _ = fmt.Fprintf(w, `{"errors":true,"items":[{"create":{"status":%d,"error":{"type":"x"}}},{"create":{"status":%d,"error":{"type":"x"}}}]}`, code, code)
	})
}

const awsInternalError = "InternalError"

func fakeS3(t *testing.T, code string, httpStatus int) *fakeDestination {
	t.Helper()
	awstest.Isolate(t)
	return hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(httpStatus)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>answered</Message></Error>`, code)
	})
}

// fakeSQS answers a batch with every entry failed at senderFault and any other request with code at httpStatus.
func fakeSQS(t *testing.T, code string, httpStatus int, senderFault bool) *fakeDestination {
	t.Helper()
	awstest.Isolate(t)
	return hostileHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.Header().Del("X-Amzn-Errortype") // the SDK takes the code from this header before the body
		if r.Header.Get("X-Amz-Target") == sqsBatchTarget {
			_, _ = fmt.Fprintf(w, `{"Successful":[],"Failed":[{"Id":"0","Code":"%[1]s","Message":"answered","SenderFault":%[2]t},`+
				`{"Id":"1","Code":"%[1]s","Message":"answered","SenderFault":%[2]t}]}`, code, senderFault)
			return
		}
		w.WriteHeader(httpStatus)
		_, _ = fmt.Fprintf(w, `{"__type":"com.amazonaws.sqs#%s","message":"answered"}`, code)
	})
}

func fakeSNS(t *testing.T, code string, httpStatus int) *fakeDestination {
	t.Helper()
	awstest.Isolate(t)
	return hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(httpStatus)
		_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>answered</Message></Error><RequestId>r</RequestId></ErrorResponse>`, code)
	})
}

// fakeKafkaCluster is a one-broker cluster leading one partition of kafkaTopic that answers every Produce with code.
func fakeKafkaCluster(t *testing.T, code int16) *fakeDestination {
	t.Helper()
	d := &fakeDestination{}
	// Versions before topic IDs, so the fake needs no identifier the client would have to match.
	supported := []kmsg.ApiVersionsResponseApiKey{
		{ApiKey: kmsg.NewPtrApiVersionsRequest().Key(), MaxVersion: 3},
		{ApiKey: kmsg.NewPtrMetadataRequest().Key(), MaxVersion: 7},
		{ApiKey: kmsg.NewPtrProduceRequest().Key(), MaxVersion: 7},
	}
	d.host = hostileKafkaBroker(t, supported, func(conn net.Conn, req kmsg.Request) kmsg.Response {
		switch req.(type) {
		case *kmsg.MetadataRequest:
			addr := conn.LocalAddr().(*net.TCPAddr)
			metadata := kmsg.NewPtrMetadataResponse()
			metadata.ControllerID = 1
			metadata.Brokers = []kmsg.MetadataResponseBroker{{NodeID: 1, Host: addr.IP.String(), Port: int32(addr.Port)}}
			metadata.Topics = []kmsg.MetadataResponseTopic{{Topic: kmsg.StringPtr(kafkaTopic), Partitions: []kmsg.MetadataResponseTopicPartition{
				{Partition: 0, Leader: 1, Replicas: []int32{1}, ISR: []int32{1}},
			}}}
			return metadata
		case *kmsg.ProduceRequest:
			d.attempts.Add(1)
			produce := kmsg.NewPtrProduceResponse()
			produce.Topics = []kmsg.ProduceResponseTopic{{Topic: kafkaTopic, Partitions: []kmsg.ProduceResponseTopicPartition{
				{Partition: 0, ErrorCode: code, BaseOffset: -1, LogAppendTime: -1, LogStartOffset: -1},
			}}}
			return produce
		default:
			return nil
		}
	})
	return d
}

func fakeAPIServer(t *testing.T, code int) *fakeDestination {
	t.Helper()
	d := hostileHTTPServer(t, code, "")
	d.host = testutil.WriteKubeconfig(t, d.host, "", "token")
	return d
}

// fakeRedis accepts the handshake and answers each RPUSH with reply.
func fakeRedis(t *testing.T, reply string) *fakeDestination {
	t.Helper()
	d := &fakeDestination{}
	d.host = hostileRESPServer(t, func(command string) string {
		if command != "RPUSH" {
			return "+OK\r\n"
		}
		d.attempts.Add(1)
		return reply
	})
	return d
}

// fakeSMTP accepts the session and the sender, then answers the only recipient with rcptReply.
func fakeSMTP(t *testing.T, rcptReply string) *fakeDestination {
	t.Helper()
	d := &fakeDestination{}
	d.host = hostileSMTPServer(t, func(verb string) []string {
		switch verb {
		case "MAIL":
			d.attempts.Add(1)
			return []string{"250 sender ok"}
		case "RCPT":
			return []string{rcptReply}
		default:
			return []string{"250 fake"}
		}
	})
	return d
}

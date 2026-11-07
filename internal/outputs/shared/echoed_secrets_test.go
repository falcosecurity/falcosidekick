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
	"bytes"
	"context"
	"encoding"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
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

// echoedSecretTimeout bounds one call against a destination the driver retries on its own.
const echoedSecretTimeout = 5 * time.Second

type echoedSecretCase struct {
	// destination starts the hostile destination and returns what config receives;
	// nil runs the output against every hostile HTTP answer.
	destination func(t *testing.T) string
	config      func(host string) map[string]any
	name        string
	typ         string // output type when it differs from name
	want        string // text of the Send error proving the destination answered, not a timeout
	noProbe     bool   // HealthCheck does not contact the destination
}

var hostileAnswers = []struct {
	name   string
	want   string
	status int
}{
	{name: "400", status: http.StatusBadRequest, want: "HTTP 400"},
	{name: "500", status: http.StatusInternalServerError, want: "HTTP 500"},
	{name: "302", status: http.StatusFound, want: "redirect"},
}

// A destination that echoes a secret in its answers must never get it into errors or logs.
func TestEveryOutputKeepsEchoedSecretsOut(t *testing.T) {
	secretHeader := map[string]any{"Authorization": map[string]any{"secrets": []string{"Bearer " + echoedSecret}}}
	tests := []echoedSecretCase{
		{name: "webhook", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{
				"host": h, "secret_endpoint": "/hook/" + echoedSecret, "bearer_token": echoedSecret,
				"query_params": map[string]any{"token": map[string]any{"secrets": []string{echoedSecret}}},
			}
		}},
		{name: "slack", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/services/T/B/" + echoedSecret}
		}},
		// Slack reports failures as text in a 200 answer.
		{name: "slack text answer", typ: "slack", noProbe: true, want: "unexpected response", destination: func(t *testing.T) string {
			return hostileHTTPServer(t, http.StatusOK, echoedSecret).host
		}, config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/services/T/B/" + echoedSecret}
		}},
		{name: "loki", config: func(h string) map[string]any {
			return map[string]any{"host": h, "bearer_token": echoedSecret, "tenant": "t"}
		}},
		{name: "elasticsearch", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": echoedSecret} }},
		{name: "elasticsearch bulk items", typ: "elasticsearch", want: "HTTP 400", destination: hostileBulkServer,
			config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": echoedSecret} }},
		{name: "alertmanager", config: func(h string) map[string]any {
			return map[string]any{"hosts": []string{h}, "username": "u", "password": echoedSecret}
		}},
		{name: "teams", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/workflows/" + echoedSecret}
		}},
		{name: "discord", config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/api/webhooks/1/" + echoedSecret}
		}},
		{name: "grafanaoncall", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/integrations/v1/formatted_webhook/" + echoedSecret + "/"}
		}},
		{name: "talon", config: func(h string) map[string]any { return map[string]any{"host": h, "headers": secretHeader} }},
		{name: "cloudevents", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "headers": secretHeader}
		}},
		{name: "pagerduty", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "routing_key": echoedSecret}
		}},
		{name: "opsgenie", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": echoedSecret} }},
		{name: "datadog", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": echoedSecret} }},
		{name: "datadog v2", typ: "datadog", config: func(h string) map[string]any {
			return map[string]any{"host": h, "api_key": echoedSecret, "app_key": echoedSecret}
		}},
		{name: "otlp", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{
				"traces": map[string]any{"endpoint": h, "headers": secretHeader},
				"logs":   map[string]any{"endpoint": h}, "metrics": map[string]any{"endpoint": h},
			}
		}},
		// The exporters return the collector's partial-success message as the error text.
		{name: "otlp partial success", typ: "otlp", noProbe: true, want: "partial success", destination: func(t *testing.T) string {
			return hostileHTTPServer(t, http.StatusOK, `{"partialSuccess":{"rejectedSpans":1,"rejectedLogRecords":1,`+
				`"rejectedDataPoints":1,"errorMessage":"`+echoedSecret+`"}}`).host
		}, config: func(h string) map[string]any {
			signal := map[string]any{"endpoint": h}
			return map[string]any{"traces": signal, "logs": signal, "metrics": signal}
		}},
		{name: "otlp grpc", typ: "otlp", noProbe: true, want: "PermissionDenied", destination: func(t *testing.T) string {
			return hostileGRPCServer(t, status.Error(codes.PermissionDenied, "denied: "+echoedSecret)).host
		}, config: func(h string) map[string]any {
			signal := map[string]any{"endpoint": h, "protocol": "grpc", "headers": secretHeader}
			return map[string]any{"traces": signal, "logs": signal, "metrics": signal}
		}},
		{name: "awss3", want: "HTTP 403", destination: hostileS3Server, config: func(h string) map[string]any {
			return awsHostileConfig(h, map[string]any{"bucket": "falco", "use_path_style": true})
		}},
		{name: "awssqs", want: "HTTP 400", destination: hostileSQSServer, config: func(h string) map[string]any {
			return awsHostileConfig(h, map[string]any{"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q"})
		}},
		{name: "awssns", want: "HTTP 403", destination: hostileSNSServer, config: func(h string) map[string]any {
			return awsHostileConfig(h, map[string]any{"topic_arn": "arn:aws:sns:us-east-1:1:t"})
		}},
		// The emulator takes no credentials; gcppubsub.TestInitRejectsUnusableCredentials covers that secret.
		{name: "gcppubsub", want: "PermissionDenied", destination: func(t *testing.T) string {
			return hostilePubSubServer(t, status.Error(codes.PermissionDenied, "user not authorized: "+echoedSecret)).host
		}, config: func(h string) map[string]any {
			return map[string]any{"project_id": "p", "topic": "falco", "emulator_host": h}
		}},
		{name: "kafka", want: "SASL_AUTHENTICATION_FAILED", destination: hostileSASLBroker, config: func(h string) map[string]any {
			return map[string]any{
				"brokers": []string{h}, "topic": "falco",
				"auth":     map[string]any{"sasl": "plain", "username": "u", "password": echoedSecret},
				"producer": map[string]any{"delivery_timeout": "1s"},
			}
		}},
		{name: "policyreport", want: "HTTP 403", destination: hostileAPIServer, config: func(h string) map[string]any {
			return map[string]any{"kubeconfig": h, "falco_namespace": "falco"}
		}},
		{name: "redis", want: "WRONGPASS", destination: func(t *testing.T) string {
			return hostileRESPServer(t, func(string) string {
				return "-WRONGPASS invalid username-password pair: " + echoedSecret + "\r\n"
			})
		}, config: func(h string) map[string]any {
			return map[string]any{"address": h, "username": "u", "password": echoedSecret}
		}},
		{name: "redis command refused", typ: "redis", want: ": ERR", destination: func(t *testing.T) string {
			return hostileRESPServer(t, func(string) string { return "-ERR " + echoedSecret + "\r\n" })
		}, config: func(h string) map[string]any { return map[string]any{"address": h} }},
		{name: "smtp", want: "server replied 535", destination: func(t *testing.T) string {
			return hostileSMTPServer(t, func(verb string) []string {
				if verb == "EHLO" {
					return []string{"250-hostile", "250 AUTH PLAIN"}
				}
				return []string{"535 5.7.8 invalid credentials: " + echoedSecret}
			})
		}, config: func(h string) map[string]any {
			return hostileSMTPConfig(h, map[string]any{"auth_mechanism": "plain", "user": "u", "password": echoedSecret})
		}},
		{name: "smtp session refused", typ: "smtp", want: "server replied 554", destination: func(t *testing.T) string {
			return hostileSMTPServer(t, func(string) []string { return []string{"554 5.7.1 " + echoedSecret} })
		}, config: func(h string) map[string]any { return hostileSMTPConfig(h, map[string]any{"auth_mechanism": "none"}) }},
		// Syslog has no credential and no reply protocol: the receiver's only text is what it writes on the wire.
		{name: "syslog", want: "invalid TLS response", destination: hostileTLSPeer, config: func(h string) map[string]any {
			cfg := hostPort(h)
			maps.Copy(cfg, map[string]any{"protocol": "tls"})
			return cfg
		}},
	}
	covered := map[string]bool{"inmemory": true} // stores in process, no destination
	for _, tt := range tests {
		covered[tt.outputType()] = true
	}
	for name := range outputTypes {
		require.True(t, covered[name], "output %s has no echoing-destination case", name)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.destination != nil {
				runEchoedSecretCase(t, &tt, tt.destination(t), tt.want)
				return
			}
			for _, answer := range hostileAnswers {
				t.Run(answer.name, func(t *testing.T) {
					runEchoedSecretCase(t, &tt, hostileHTTPServer(t, answer.status, hostileJSON).host, answer.want)
				})
			}
		})
	}
}

func (c *echoedSecretCase) outputType() string {
	if c.typ != "" {
		return c.typ
	}
	return c.name
}

func runEchoedSecretCase(t *testing.T, tt *echoedSecretCase, host, want string) {
	t.Helper()
	var logs lockedBuffer
	deps := output.Deps{Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	driver, err := outputTypes[tt.outputType()].New(tt.config(host), deps)
	require.NoError(t, err)
	require.NoError(t, driver.Init(context.Background()))
	t.Cleanup(func() {
		assertNoEchoedSecret(t, "Close", driver.Close())
		assert.NotContains(t, logs.String(), echoedSecret, "logs after Close")
	})
	ctx, cancel := context.WithTimeout(context.Background(), echoedSecretTimeout)
	defer cancel()

	err = driver.Send(ctx, testutil.CreateValidEvent())
	require.Error(t, err, "Send")
	assert.Contains(t, err.Error(), want, "Send")
	assertNoEchoedSecret(t, "Send", err)
	if batch, ok := driver.(output.BatchSender); ok {
		err = batch.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
		require.Error(t, err, "SendBatch")
		assertNoEchoedSecret(t, "SendBatch", err)
	}
	if !tt.noProbe {
		err = driver.HealthCheck(ctx)
		require.Error(t, err, "HealthCheck")
		assertNoEchoedSecret(t, "HealthCheck", err)
	}
	assert.NotContains(t, logs.String(), echoedSecret, "logs")
}

func assertNoEchoedSecret(t *testing.T, call string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	rendered := []string{err.Error(), fmt.Sprintf("%v %+v %s %q", err, err, err, err)}
	if marshaler, ok := err.(encoding.TextMarshaler); ok {
		text, marshalErr := marshaler.MarshalText()
		require.NoError(t, marshalErr, call)
		rendered = append(rendered, string(text))
	}
	for _, text := range rendered {
		assert.NotContains(t, text, echoedSecret, call)
	}
}

type lockedBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var hostileJSON = `{"error":{"type":"` + echoedSecret + `","message":"` + echoedSecret + `"},"message":"` + echoedSecret + `"}`

// hostileBulkServer accepts a bulk request and fails every item with an error type of its own.
func hostileBulkServer(t *testing.T) string {
	t.Helper()
	item := `{"create":{"status":%d,"error":{"type":"` + echoedSecret + `","reason":"` + echoedSecret + `"}}}`
	return hostileHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_bulk") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, hostileJSON)
			return
		}
		_, _ = fmt.Fprintf(w, `{"errors":true,"items":[`+item+`,`+item+`]}`, http.StatusBadRequest, http.StatusInternalServerError)
	}).host
}

func awsHostileConfig(endpoint string, extra map[string]any) map[string]any {
	cfg := awstest.Config(endpoint, map[string]any{"secret_access_key": echoedSecret, "session_token": echoedSecret})
	maps.Copy(cfg, extra)
	return cfg
}

func hostileS3Server(t *testing.T) string {
	t.Helper()
	awstest.Isolate(t)
	return hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>`+
			echoedSecret+`</Message><RequestId>`+echoedSecret+`</RequestId><HostId>`+echoedSecret+`</HostId></Error>`)
	}).host
}

// hostileSQSServer fails each batch entry with a code of its own and refuses every other request.
func hostileSQSServer(t *testing.T) string {
	t.Helper()
	awstest.Isolate(t)
	entry := `{"Id":"%d","Code":"` + echoedSecret + `","Message":"` + echoedSecret + `","SenderFault":%t}`
	return hostileHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if r.Header.Get("X-Amz-Target") == sqsBatchTarget {
			_, _ = fmt.Fprintf(w, `{"Successful":[],"Failed":[`+entry+`,`+entry+`]}`, 0, true, 1, false)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"com.amazonaws.sqs#`+echoedSecret+`","message":"`+echoedSecret+`"}`)
	}).host
}

func hostileSNSServer(t *testing.T) string {
	t.Helper()
	awstest.Isolate(t)
	return hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>`+echoedSecret+`</Code><Message>`+
			echoedSecret+`</Message></Error><RequestId>`+echoedSecret+`</RequestId></ErrorResponse>`)
	}).host
}

// hostileAPIServer returns a kubeconfig whose token is the secret, for an API server that echoes it in every Status.
func hostileAPIServer(t *testing.T) string {
	t.Helper()
	server := hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"`+echoedSecret+
			`","message":"`+echoedSecret+`","details":{"causes":[{"message":"`+echoedSecret+`"}]},"code":403}`)
	})
	return testutil.WriteKubeconfig(t, server.host, "", echoedSecret)
}

// hostileTLSPeer writes the secret where a TLS client expects the server hello.
func hostileTLSPeer(t *testing.T) string {
	t.Helper()
	return hostileTCPServer(t, func(conn net.Conn) {
		if _, err := io.WriteString(conn, echoedSecret+"\r\n"); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
	})
}

// hostileSASLBroker rejects SASL PLAIN with a message that echoes the password.
func hostileSASLBroker(t *testing.T) string {
	t.Helper()
	requests := []kmsg.Request{
		kmsg.NewPtrApiVersionsRequest(), kmsg.NewPtrSASLHandshakeRequest(), kmsg.NewPtrSASLAuthenticateRequest(),
		kmsg.NewPtrMetadataRequest(), kmsg.NewPtrProduceRequest(),
	}
	supported := make([]kmsg.ApiVersionsResponseApiKey, 0, len(requests))
	for _, req := range requests {
		supported = append(supported, kmsg.ApiVersionsResponseApiKey{ApiKey: req.Key(), MaxVersion: req.MaxVersion()})
	}
	return hostileKafkaBroker(t, supported, func(_ net.Conn, req kmsg.Request) kmsg.Response {
		switch req.(type) {
		case *kmsg.SASLHandshakeRequest:
			handshake := kmsg.NewPtrSASLHandshakeResponse()
			handshake.SupportedMechanisms = []string{"PLAIN"}
			return handshake
		case *kmsg.SASLAuthenticateRequest:
			authenticate := kmsg.NewPtrSASLAuthenticateResponse()
			authenticate.ErrorCode = kerr.SaslAuthenticationFailed.Code
			authenticate.ErrorMessage = kmsg.StringPtr("Authentication failed: invalid password " + echoedSecret)
			return authenticate
		default:
			return nil
		}
	})
}

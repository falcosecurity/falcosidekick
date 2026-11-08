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

package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestConstructorRejectsNonHTTPHostsWithoutEchoingThem(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	_, err := OutputType.New(map[string]any{
		"hosts": []string{"http://am:9093", "ftp://u:" + sentinel + "@am:9093"},
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hosts: entry [1] scheme must be http or https")
	assert.NotContains(t, err.Error(), sentinel)
}

func TestFanOutSafeDiagnostics(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, allFail := range []bool{false, true} {
			name := format + "/partial"
			if allFail {
				name = format + "/all failed"
			}
			t.Run(name, func(t *testing.T) {
				var logs bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&logs, nil)
				if format == "json" {
					handler = slog.NewJSONHandler(&logs, nil)
				}
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if !allFail && strings.HasPrefix(r.Host, "localhost") {
						w.WriteHeader(http.StatusOK)
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("RESPONSE_SECRET"))
				}))
				t.Cleanup(server.Close)
				d, err := createOutput(map[string]any{
					"hosts": []string{
						server.URL,
						strings.Replace(server.URL, "127.0.0.1", "localhost", 1),
					},
					"secret_endpoint": "/PATH_SECRET",
					"query_params":    map[string]any{"token": map[string]any{"secrets": []string{"QUERY_SECRET"}}},
				}, output.Deps{Logger: slog.New(handler)})
				require.NoError(t, err)
				err = d.Send(context.Background(), testutil.CreateValidEvent())
				if allFail {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "all 2 hosts failed")
					assert.Contains(t, err.Error(), "HTTP 401 Unauthorized")
					var diagnostic *shared.DeliveryError
					assert.ErrorAs(t, err, &diagnostic)
				} else {
					require.NoError(t, err, "one successful host must still make delivery succeed")
					assert.Contains(t, logs.String(), "partial fan-out")
				}
				assert.EqualValues(t, 2, requests.Load())
				assert.Contains(t, logs.String(), "HTTP 401 Unauthorized")
				assert.Contains(t, logs.String(), "host_index")
				if format == "text" {
					assert.Contains(t, logs.String(), "host_index=0")
				} else {
					assert.Contains(t, logs.String(), `"host_index":0`)
				}
				for _, secret := range []string{"PATH_SECRET", "QUERY_SECRET", "RESPONSE_SECRET", server.URL} {
					assert.NotContains(t, logs.String(), secret)
					if err != nil {
						assert.NotContains(t, err.Error(), secret)
					}
				}
			})
		}
	}
}

func TestFanOutCancellationPreservesCause(t *testing.T) {
	var logs bytes.Buffer
	d, err := createOutput(map[string]any{
		"hosts":           []string{"http://127.0.0.1", "http://localhost"},
		"secret_endpoint": "/PATH_SECRET",
		"query_params":    map[string]any{"token": map[string]any{"secrets": []string{"QUERY_SECRET"}}},
	}, output.Deps{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = d.Send(ctx, testutil.CreateValidEvent())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "request canceled")
	assert.NotContains(t, err.Error(), "PATH_SECRET")
	assert.NotContains(t, err.Error(), "QUERY_SECRET")
	assert.NotContains(t, logs.String(), "PATH_SECRET")
	assert.NotContains(t, logs.String(), "QUERY_SECRET")
}

func TestAlertmanagerCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "hosts", AddressSlice: true},
		{Name: "returns error on server 500", AddressField: "hosts", AddressSlice: true, MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestAlertmanagerPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "sends alert with required fields",
			AddressField: "hosts",
			AddressSlice: true,
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				require.Len(t, alerts, 1)
				assert.NotEmpty(t, alerts[0].Labels["alertname"], "must include alertname label")
				assert.NotEmpty(t, alerts[0].Labels["rule"])
				assert.NotEmpty(t, alerts[0].Labels["severity"])
				assert.NotEmpty(t, alerts[0].StartsAt, "must include startsAt")
				assert.NotEmpty(t, alerts[0].Annotations["info"])
			},
		},
		{
			Name:         "posts to v2 API endpoint by default",
			AddressField: "hosts",
			AddressSlice: true,
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "/api/v2/alerts", req.URL.Path)
			},
		},
		{
			Name:         "includes extra labels",
			AddressField: "hosts",
			AddressSlice: true,
			Config:       map[string]any{"extra_labels": map[string]string{"env": "prod"}},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				assert.Equal(t, "prod", alerts[0].Labels["env"])
			},
		},
		{
			Name:         "sets endsAt when expires_after configured",
			AddressField: "hosts",
			AddressSlice: true,
			Config:       map[string]any{"expires_after": 300},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				assert.NotEmpty(t, alerts[0].EndsAt)
			},
		},
		{
			Name:         "sets custom headers",
			AddressField: "hosts",
			AddressSlice: true,
			Config: map[string]any{"headers": map[string]any{
				"X-Auth": map[string]any{"secrets": []string{"token123"}},
			}},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "token123", req.Header.Get("X-Auth"))
			},
		},
	})
}

func TestAlertmanagerCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, output.Deps{})
	assert.Error(t, err, "missing hosts must fail")
}

func TestFanOutSendsToAllHosts(t *testing.T) {
	var count1, count2 atomic.Int32

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count1.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count2.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	o := &driver{
		cfg: config{
			HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
			Hosts:            []string{server1.URL, server2.URL},
		},
		sender: testutil.MustNewSender(t, "alertmanager"),
		logger: slog.Default().With("output", "alertmanager"),
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	require.NoError(t, err)
	assert.Equal(t, int32(1), count1.Load(), "host 1 must receive the alert")
	assert.Equal(t, int32(1), count2.Load(), "host 2 must receive the alert")
}

func TestFanOutSucceedsIfOneHostWorks(t *testing.T) {
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("down"))
	}))
	defer badServer.Close()

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer goodServer.Close()

	o := &driver{
		cfg: config{
			HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
			Hosts:            []string{badServer.URL, goodServer.URL},
		},
		sender: testutil.MustNewSender(t, "alertmanager"),
		logger: slog.Default().With("output", "alertmanager"),
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	assert.NoError(t, err, "must succeed when at least one host works")
}

func TestFanOutFailsWhenAllHostsFail(t *testing.T) {
	answer := func(status int) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("down"))
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	unavailable, rejected := answer(http.StatusInternalServerError), answer(http.StatusBadRequest)
	for _, tc := range []struct {
		name      string
		hosts     []string
		permanent bool
	}{
		{name: "transient", hosts: []string{unavailable, unavailable}},
		{name: "one host may recover", hosts: []string{rejected, unavailable}},
		{name: "every host rejects", hosts: []string{rejected, rejected}, permanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &driver{
				cfg: config{
					HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
					Hosts:            tc.hosts,
				},
				sender: testutil.MustNewSender(t, "alertmanager"),
				logger: slog.New(slog.DiscardHandler),
			}
			err := o.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "alertmanager send: all 2 hosts failed, last: HTTP ")
			assert.Equal(t, tc.permanent, output.IsPermanent(err))
		})
	}
}

func TestSingleHostSkipsFanOut(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &driver{
		cfg: config{
			HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
			Hosts:            []string{server.URL},
		},
		sender: testutil.MustNewSender(t, "alertmanager"),
		logger: slog.Default().With("output", "alertmanager"),
	}

	require.NoError(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, int32(1), callCount.Load())
}

func TestAlertmanagerHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/-/healthy", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &driver{
		cfg: config{
			HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
			Hosts:            []string{server.URL},
		},
		sender: testutil.MustNewSender(t, "alertmanager"),
		logger: slog.Default().With("output", "alertmanager"),
	}

	assert.NoError(t, o.HealthCheck(context.Background()))
}

func TestAlertmanagerHealthCheckNoHosts(t *testing.T) {
	o := &driver{cfg: config{}}
	assert.Error(t, o.HealthCheck(context.Background()))
}

func statusServer(t *testing.T, status *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFanOutWarningFollowsPartialFailure(t *testing.T) {
	var badStatus, goodStatus atomic.Int32
	badStatus.Store(http.StatusInternalServerError)
	goodStatus.Store(http.StatusOK)
	bad, good := statusServer(t, &badStatus), statusServer(t, &goodStatus)

	o := &driver{
		cfg: config{
			HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
			Hosts:            []string{bad.URL, good.URL},
		},
		sender: testutil.MustNewSender(t, "alertmanager"),
		logger: slog.New(slog.DiscardHandler),
	}
	var warnings []string
	o.SetWarningHandler(func(warning string) { warnings = append(warnings, warning) })

	require.NoError(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "1 of 2 hosts failed")
	assert.Contains(t, warnings[0], "HTTP 500")

	badStatus.Store(http.StatusOK)
	require.NoError(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, []string{warnings[0], ""}, warnings, "full delivery clears the warning")
}

func TestAlertmanagerHealthCheckClassifiesHosts(t *testing.T) {
	var ok, notFound, unavailable atomic.Int32
	ok.Store(http.StatusOK)
	notFound.Store(http.StatusNotFound)
	unavailable.Store(http.StatusServiceUnavailable)
	okServer, notFoundServer, unavailableServer := statusServer(t, &ok), statusServer(t, &notFound), statusServer(t, &unavailable)

	for _, tc := range []struct {
		name           string
		wantErrContain string
		hosts          []string
		misconfigured  bool
	}{
		{name: "all healthy", hosts: []string{okServer.URL, okServer.URL}},
		{name: "one unavailable", hosts: []string{okServer.URL, unavailableServer.URL}, wantErrContain: "1 of 2 hosts"},
		{name: "wrong path on one host", hosts: []string{okServer.URL, notFoundServer.URL}, misconfigured: true, wantErrContain: "HTTP 404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &driver{
				cfg: config{
					HTTPTargetConfig: shared.HTTPTargetConfig{Endpoint: defaultEndpoint},
					Hosts:            tc.hosts,
				},
				sender: testutil.MustNewSender(t, "alertmanager"),
				logger: slog.New(slog.DiscardHandler),
			}
			err := o.HealthCheck(context.Background())
			if tc.wantErrContain == "" {
				assert.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErrContain)
			assert.Equal(t, tc.misconfigured, errors.Is(err, output.ErrMisconfigured))
		})
	}
}

func TestAlertmanagerCustomEndpoint(t *testing.T) {
	d, err := createOutput(map[string]any{
		"hosts":    []string{"http://am:9093"},
		"endpoint": "/api/v2/alerts",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	assert.Equal(t, "/api/v2/alerts", o.cfg.DeliveryRoute())
}

func TestAlertmanagerInit(t *testing.T) {
	o := &driver{}
	assert.NoError(t, o.Init(context.Background()))
}

func TestAlertmanagerClose(t *testing.T) {
	d, err := OutputType.New(map[string]any{"hosts": []string{"http://127.0.0.1:1"}}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.Close())
	assert.NoError(t, d.Close(), "Close is idempotent")
}

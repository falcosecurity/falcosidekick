// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/base64"
	"encoding/json"
	"expvar"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// redirectTransport rewrites the scheme and host of every request to targetURL
// This lets GCPChronicleIngest build the real Chronicle URL but have the HTTP
// request land on the test server.
type redirectTransport struct {
	base      http.RoundTripper
	targetURL string
}

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	target, _ := url.Parse(r.targetURL)
	req2.URL.Scheme = target.Scheme
	req2.URL.Host = target.Host
	return r.base.RoundTrip(req2)
}

type noopCounter struct{}

func (noopCounter) With(...attribute.KeyValue) otlpmetrics.Counter { return noopCounter{} }
func (noopCounter) Inc()                                           {}

// newChronicleTestClient builds a Client wired for testing GCPChronicleIngest.
// Pass serverURL="" to get a nil GCPChronicleClient; pass tokenSource=nil for nil-guard tests.
// Each call must use a unique expvarName to avoid global expvar conflicts.
func newChronicleTestClient(t *testing.T, serverURL string, tokenSource oauth2.TokenSource, expvarName string) *Client {
	t.Helper()
	config := &types.Configuration{}
	config.GCP.Chronicle.Region = "us"
	config.GCP.Chronicle.ProjectID = "test-project"
	config.GCP.Chronicle.InstanceID = "test-instance"
	config.GCP.Chronicle.LogType = "FALCO_IDS"

	stats := &types.Statistics{}
	stats.GCPChronicle = expvar.NewMap(expvarName)

	var httpClient *http.Client
	if serverURL != "" {
		httpClient = &http.Client{
			Transport: &redirectTransport{base: http.DefaultTransport, targetURL: serverURL},
		}
	}

	return &Client{
		OutputType:         "GCP",
		Config:             config,
		Stats:              stats,
		PromStats:          &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: expvarName + "_prom", Help: "test"}, []string{"destination", "status"})},
		OTLPMetrics:        &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
		GCPChronicleClient: httpClient,
		GCPTokenSource:     tokenSource,
	}
}

// getExpvarInt64 reads an int64 value from an expvar.Map, returning 0 if the key is absent.
func getExpvarInt64(t *testing.T, m *expvar.Map, key string) int64 {
	t.Helper()
	v := m.Get(key)
	if v == nil {
		return 0
	}
	var n int64
	_, _ = fmt.Sscanf(v.String(), "%d", &n)
	return n
}

func TestGCPChronicleIngest_Success(t *testing.T) {
	// Create a test server that validates the request
	handlerCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify endpoint path - matches API format: /v1beta/{parent}/logTypes/{logType}/logs:import
		require.True(t, strings.HasSuffix(r.URL.Path, "/v1beta/projects/test-project/locations/us/instances/test-instance/logTypes/FALCO_IDS/logs:import"))

		// Verify Content-Type
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify Authorization header
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		// Verify request body structure (per API docs: inlineSource -> logs -> {data, logEntryTime, collectionTime})
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		inlineSource, ok := body["inlineSource"].(map[string]interface{})
		require.True(t, ok)
		logs, ok := inlineSource["logs"].([]interface{})
		require.True(t, ok)
		require.Len(t, logs, 1)
		logEntry := logs[0].(map[string]interface{})
		require.Contains(t, logEntry, "data")
		require.Contains(t, logEntry, "logEntryTime")
		require.Contains(t, logEntry, "collectionTime")

		// Verify data is base64-encoded and contains valid FalcoPayload JSON
		decoded, err := base64.StdEncoding.DecodeString(logEntry["data"].(string))
		require.NoError(t, err)
		var fp types.FalcoPayload
		require.NoError(t, json.Unmarshal(decoded, &fp))
		require.Equal(t, "Test rule", fp.Rule)

		// Verify timestamp formats (RFC3339)
		_, err = time.Parse(time.RFC3339, logEntry["logEntryTime"].(string))
		require.NoError(t, err)
		_, err = time.Parse(time.RFC3339, logEntry["collectionTime"].(string))
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create test FalcoPayload and call GCPChronicleIngest
	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client := newChronicleTestClient(t, ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), "outputs.gcpchronicle.test.success")
	client.GCPChronicleIngest(falcoPayload)

	// Verify the handler was actually invoked and stats reflect success
	require.True(t, handlerCalled, "server handler should have been invoked")
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, OK))
	require.Equal(t, int64(0), getExpvarInt64(t, client.Stats.GCPChronicle, Error))
}

func TestGCPChronicleIngest_Non200(t *testing.T) {
	// Verify that a non-200 response from Chronicle API is handled as error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client := newChronicleTestClient(t, ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), "outputs.gcpchronicle.test.non200")
	client.GCPChronicleIngest(falcoPayload)

	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, Error))
	require.Equal(t, int64(0), getExpvarInt64(t, client.Stats.GCPChronicle, OK))
}

// Verify nil token source triggers early return without making an HTTP request
func TestGCPChronicleIngest_NilTokenSource(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when token source is nil")
	}))
	defer ts.Close()

	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client := newChronicleTestClient(t, ts.URL, nil, "outputs.gcpchronicle.test.niltoken")
	client.GCPChronicleIngest(falcoPayload)

	// Nil guard returns before Total is incremented
	require.Equal(t, int64(0), getExpvarInt64(t, client.Stats.GCPChronicle, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, Error))
}

// Verify nil HTTP client triggers early return without making an HTTP request
func TestGCPChronicleIngest_NilClient(t *testing.T) {
	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client := newChronicleTestClient(t, "", oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), "outputs.gcpchronicle.test.nilclient")
	client.GCPChronicleIngest(falcoPayload)

	require.Equal(t, int64(0), getExpvarInt64(t, client.Stats.GCPChronicle, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, Error))
}

// Verify that region, projectID, instanceID, and logType are correctly interpolated into the API URL
func TestGCPChronicleIngest_EndpointConstruction(t *testing.T) {
	testCases := []struct {
		name         string
		region       string
		projectID    string
		instanceID   string
		logType      string
		expectedPath string
	}{
		{
			name:         "US region",
			region:       "us",
			projectID:    "my-project",
			instanceID:   "instance-123",
			logType:      "FALCO_IDS",
			expectedPath: "/v1beta/projects/my-project/locations/us/instances/instance-123/logTypes/FALCO_IDS/logs:import",
		},
		{
			name:         "Europe region",
			region:       "europe-west12",
			projectID:    "my-project",
			instanceID:   "instance-456",
			logType:      "FALCO_IDS",
			expectedPath: "/v1beta/projects/my-project/locations/europe-west12/instances/instance-456/logTypes/FALCO_IDS/logs:import",
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var receivedPath string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			var falcoPayload types.FalcoPayload
			require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

			client := newChronicleTestClient(t, ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}),
				fmt.Sprintf("outputs.gcpchronicle.test.endpoint.%d", i))
			client.Config.GCP.Chronicle.Region = tc.region
			client.Config.GCP.Chronicle.ProjectID = tc.projectID
			client.Config.GCP.Chronicle.InstanceID = tc.instanceID
			client.Config.GCP.Chronicle.LogType = tc.logType

			client.GCPChronicleIngest(falcoPayload)

			require.True(t, strings.HasSuffix(receivedPath, tc.expectedPath),
				"expected path suffix %s, got %s", tc.expectedPath, receivedPath)
			require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.GCPChronicle, OK))
		})
	}
}

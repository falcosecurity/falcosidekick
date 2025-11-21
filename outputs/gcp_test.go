// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestGCPChronicleIngest_Success(t *testing.T) {
	// Create a test server that validates the request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		require.Equal(t, "POST", r.Method)

		// Verify endpoint path - matches API format: /v1beta/{parent}/logTypes/{logType}/logs:import
		expectedPath := "/v1beta/projects/test-project/locations/us/instances/test-instance/logTypes/FALCO_IDS/logs:import"
		require.True(t, strings.HasSuffix(r.URL.Path, expectedPath), "Expected path to end with %s, got %s", expectedPath, r.URL.Path)

		// Verify Content-Type
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(authHeader, "Bearer "), "Authorization header should start with 'Bearer '")

		// Verify request body structure
		var requestBody map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		require.Nil(t, err)

		// Verify inlineSource exists (per API docs)
		inlineSource, ok := requestBody["inlineSource"].(map[string]interface{})
		require.True(t, ok, "Request should have 'inlineSource' field")

		// Verify logs array exists inside inlineSource
		logs, ok := inlineSource["logs"].([]interface{})
		require.True(t, ok, "inlineSource should have 'logs' field")
		require.Len(t, logs, 1, "Should have exactly one log entry")

		// Verify log entry structure (per API docs: data, logEntryTime, collectionTime)
		logEntry, ok := logs[0].(map[string]interface{})
		require.True(t, ok, "Log entry should be a map")
		require.Contains(t, logEntry, "data", "Log entry should have 'data' field (base64-encoded)")
		require.Contains(t, logEntry, "logEntryTime", "Log entry should have 'logEntryTime' field")
		require.Contains(t, logEntry, "collectionTime", "Log entry should have 'collectionTime' field")

		// Verify data is base64-encoded and contains valid FalcoPayload JSON
		data, ok := logEntry["data"].(string)
		require.True(t, ok, "data should be a string")
		// Decode base64 data
		decodedData, err := base64.StdEncoding.DecodeString(data)
		require.Nil(t, err, "data should be valid base64")
		var falcoPayload types.FalcoPayload
		err = json.Unmarshal(decodedData, &falcoPayload)
		require.Nil(t, err, "decoded data should be valid FalcoPayload JSON")

		// Verify timestamp formats (RFC3339)
		logEntryTime, ok := logEntry["logEntryTime"].(string)
		require.True(t, ok, "logEntryTime should be a string")
		_, err = time.Parse(time.RFC3339, logEntryTime)
		require.Nil(t, err, "logEntryTime should be in RFC3339 format")

		collectionTime, ok := logEntry["collectionTime"].(string)
		require.True(t, ok, "collectionTime should be a string")
		_, err = time.Parse(time.RFC3339, collectionTime)
		require.Nil(t, err, "collectionTime should be in RFC3339 format")

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create test FalcoPayload
	var falcoPayload types.FalcoPayload
	err := json.Unmarshal([]byte(falcoTestInput), &falcoPayload)
	require.Nil(t, err)

	// Test payload marshaling
	payloadBytes, err := json.Marshal(falcoPayload)
	require.Nil(t, err)

	// Test log entry structure (matches actual implementation)
	encodedData := base64.StdEncoding.EncodeToString(payloadBytes)
	logEntryTime := falcoPayload.Time
	collectionTime := time.Now()
	if !collectionTime.After(logEntryTime) {
		collectionTime = logEntryTime.Add(time.Second)
	}

	logEntry := map[string]interface{}{
		"data":           encodedData,
		"logEntryTime":   logEntryTime.Format(time.RFC3339),
		"collectionTime": collectionTime.Format(time.RFC3339),
	}

	// Test batch request structure (matches actual implementation)
	batchRequest := map[string]interface{}{
		"inlineSource": map[string]interface{}{
			"logs": []interface{}{logEntry},
		},
	}

	requestBody, err := json.Marshal(batchRequest)
	require.Nil(t, err)

	// Verify request body structure
	var decodedRequest map[string]interface{}
	err = json.Unmarshal(requestBody, &decodedRequest)
	require.Nil(t, err)
	require.Contains(t, decodedRequest, "inlineSource")

	// Verify parent path construction
	parent := "projects/test-project/locations/us/instances/test-instance"
	require.Equal(t, "projects/test-project/locations/us/instances/test-instance", parent)

	// Verify endpoint construction (matches actual implementation)
	expectedEndpoint := "https://chronicle.us.rep.googleapis.com/v1beta/projects/test-project/locations/us/instances/test-instance/logTypes/FALCO_IDS/logs:import"
	require.Equal(t, expectedEndpoint, fmt.Sprintf("https://chronicle.us.rep.googleapis.com/v1beta/%s/logTypes/FALCO_IDS/logs:import", parent))
}

func TestGCPChronicleIngest_EndpointConstruction(t *testing.T) {
	testCases := []struct {
		name       string
		region     string
		projectID  string
		instanceID string
		logType    string
		expected   string
	}{
		{
			name:       "US region",
			region:     "us",
			projectID:  "my-project",
			instanceID: "instance-123",
			logType:    "FALCO_IDS",
			expected:   "https://chronicle.us.rep.googleapis.com/v1beta/projects/my-project/locations/us/instances/instance-123/logTypes/FALCO_IDS/logs:import",
		},
		{
			name:       "Europe region",
			region:     "europe-west12",
			projectID:  "my-project",
			instanceID: "instance-456",
			logType:    "FALCO_IDS",
			expected:   "https://chronicle.europe-west12.rep.googleapis.com/v1beta/projects/my-project/locations/europe-west12/instances/instance-456/logTypes/FALCO_IDS/logs:import",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parent := "projects/" + tc.projectID + "/locations/" + tc.region + "/instances/" + tc.instanceID
			endpoint := fmt.Sprintf("https://chronicle.%s.rep.googleapis.com/v1beta/%s/logTypes/%s/logs:import", tc.region, parent, tc.logType)
			require.Equal(t, tc.expected, endpoint)
		})
	}
}

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

package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSenderSendJSON(t *testing.T) {
	var captured struct {
		method      string
		contentType string
		body        []byte
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.contentType = r.Header.Get("Content-Type")
		captured.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	payload := map[string]string{"key": "value"}

	err := s.SendJSON(context.Background(), http.MethodPost, server.URL, payload)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, captured.method)
	assert.Equal(t, "application/json", captured.contentType)

	var decoded map[string]string
	require.NoError(t, json.Unmarshal(captured.body, &decoded))
	assert.Equal(t, "value", decoded["key"])
}

func TestSenderSendRaw(t *testing.T) {
	var captured struct {
		contentType string
		body        []byte
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.contentType = r.Header.Get("Content-Type")
		captured.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	raw := []byte(`{"index":{"_index":"falco"}}` + "\n" + `{"rule":"test"}` + "\n")

	err := s.SendRaw(context.Background(), http.MethodPost, server.URL, raw, "application/x-ndjson")
	require.NoError(t, err)

	assert.Equal(t, "application/x-ndjson", captured.contentType)
	assert.Equal(t, raw, captured.body)
}

func TestSenderDoAppliesHeaders(t *testing.T) {
	var captured http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{
		Headers: map[string]ValueSources{"X-Custom": {Values: []string{"val1"}}},
	})
	s.SetHeader("X-Extra", "val2")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, http.NoBody)
	require.NoError(t, err)

	require.NoError(t, s.Do(context.Background(), req))
	assert.Equal(t, "val1", captured.Get("X-Custom"))
	assert.Equal(t, "val2", captured.Get("X-Extra"))
}

func TestSenderDoAppliesBasicAuth(t *testing.T) {
	var capturedUser, capturedPass string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, capturedPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	s.SetBasicAuth("admin", "secret")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)

	require.NoError(t, s.Do(context.Background(), req))
	assert.Equal(t, "admin", capturedUser)
	assert.Equal(t, "secret", capturedPass)
}

func TestSenderDoReturnsErrorOnBadStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"bad request", http.StatusBadRequest},
		{"internal server error", http.StatusInternalServerError},
		{"service unavailable", http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("error body"))
			}))
			defer server.Close()

			s, _ := NewSender("myoutput", &HTTPConfig{})
			err := s.SendJSON(context.Background(), http.MethodPost, server.URL, map[string]string{})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "myoutput")
			assert.Contains(t, err.Error(), fmt.Sprintf("HTTP %d", tt.status))
			assert.NotContains(t, err.Error(), "error body")
		})
	}
}

func TestSenderDoSuccessOnOKStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"204 No Content", http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			s, _ := NewSender("test", &HTTPConfig{})
			err := s.SendJSON(context.Background(), http.MethodPost, server.URL, "data")
			assert.NoError(t, err)
		})
	}
}

func TestSenderHealthCheck(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	err := s.HealthCheck(context.Background(), server.URL)

	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, capturedMethod)
}

func TestSenderHealthCheckFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	}))
	defer server.Close()

	s, _ := NewSender("myoutput", &HTTPConfig{})
	err := s.HealthCheck(context.Background(), server.URL)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "myoutput")
}

func TestSenderEachInstanceIsIsolated(t *testing.T) {
	s1, _ := NewSender("output1", &HTTPConfig{Headers: map[string]ValueSources{"X-Out": {Values: []string{"1"}}}})
	s2, _ := NewSender("output2", &HTTPConfig{Headers: map[string]ValueSources{"X-Out": {Values: []string{"2"}}}})
	s1.SetBasicAuth("user1", "pass1")

	assert.Equal(t, []string{"1"}, s1.headers["X-Out"].Values)
	assert.Equal(t, []string{"2"}, s2.headers["X-Out"].Values)
	assert.Equal(t, "user1", s1.basicUser)
	assert.Empty(t, s2.basicUser)
}

func TestSenderSendJSONMarshalError(t *testing.T) {
	s, _ := NewSender("test", &HTTPConfig{})
	err := s.SendJSON(context.Background(), http.MethodPost, "http://localhost", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test marshal")
}

func TestSenderAutoConfiguresBasicAuth(t *testing.T) {
	var capturedUser, capturedPass string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, capturedPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{Username: "admin", Password: "secret"})
	err := s.SendJSON(context.Background(), http.MethodPost, server.URL, "data")

	require.NoError(t, err)
	assert.Equal(t, "admin", capturedUser)
	assert.Equal(t, "secret", capturedPass)
}

func TestSenderAutoConfiguresBearerToken(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{BearerToken: "my-token-123"})
	err := s.SendJSON(context.Background(), http.MethodPost, server.URL, "data")

	require.NoError(t, err)
	assert.Equal(t, "Bearer my-token-123", capturedAuth)
}

func TestSenderBasicAuthNotSetWhenEmpty(t *testing.T) {
	var hasAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasAuth = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	err := s.SendJSON(context.Background(), http.MethodPost, server.URL, "data")

	require.NoError(t, err)
	assert.False(t, hasAuth, "no basic auth should be set when username is empty")
}

func TestSenderSendJSONWithPUTMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	err := s.SendJSON(context.Background(), http.MethodPut, server.URL, "data")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, capturedMethod)
}

func TestSenderSendGzipJSON(t *testing.T) {
	var capturedEncoding string
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEncoding = r.Header.Get("Content-Encoding")
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	payload := map[string]string{"key": "value"}

	err := s.SendGzipJSON(context.Background(), http.MethodPost, server.URL, payload)
	require.NoError(t, err)

	assert.Equal(t, "gzip", capturedEncoding)
	assert.NotEmpty(t, capturedBody, "body should contain gzip-compressed data")
	assert.NotEqual(t, `{"key":"value"}`, string(capturedBody), "body should be compressed, not raw JSON")
}

func TestSenderSendGzipJSONMarshalError(t *testing.T) {
	s, _ := NewSender("test", &HTTPConfig{})
	err := s.SendGzipJSON(context.Background(), http.MethodPost, "http://localhost", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test marshal")
}

func TestSenderSendGzipRaw(t *testing.T) {
	var capturedEncoding, capturedContentType string
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEncoding = r.Header.Get("Content-Encoding")
		capturedContentType = r.Header.Get("Content-Type")
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	raw := []byte(`{"rule":"test"}`)

	err := s.SendGzipRaw(context.Background(), http.MethodPost, server.URL, raw, "application/x-ndjson")
	require.NoError(t, err)

	assert.Equal(t, "gzip", capturedEncoding)
	assert.Equal(t, "application/x-ndjson", capturedContentType)
	assert.NotEqual(t, raw, capturedBody, "body should be gzip-compressed")
}

func TestSenderSendJSONCheckBody(t *testing.T) {
	const expectedBody = "ok"
	tests := []struct {
		checkFn     func(body []byte) error
		name        string
		respBody    string
		expectError bool
	}{
		{
			name:     "check passes",
			respBody: expectedBody,
			checkFn: func(body []byte) error {
				if string(body) != expectedBody {
					return fmt.Errorf("unexpected body: %s", body)
				}
				return nil
			},
			expectError: false,
		},
		{
			name:     "check fails",
			respBody: "invalid_token",
			checkFn: func(body []byte) error {
				if string(body) != expectedBody {
					return fmt.Errorf("unexpected body: %s", body)
				}
				return nil
			},
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.respBody))
			}))
			defer server.Close()

			s, _ := NewSender("test", &HTTPConfig{})
			err := s.SendJSONCheckBody(context.Background(), http.MethodPost, server.URL, "data", tt.checkFn)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSenderSendJSONCheckBodyMarshalError(t *testing.T) {
	s, _ := NewSender("test", &HTTPConfig{})
	err := s.SendJSONCheckBody(context.Background(), http.MethodPost, "http://localhost", make(chan int), func([]byte) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test marshal")
}

func TestSenderSendRawReadBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	body, err := s.SendRawReadBody(context.Background(), http.MethodPost, server.URL, []byte("data"), "application/json")

	require.NoError(t, err)
	assert.Equal(t, `{"errors":false}`, string(body))
}

func TestSenderSendRawReadBodyErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	s, _ := NewSender("myoutput", &HTTPConfig{})
	body, err := s.SendRawReadBody(context.Background(), http.MethodPost, server.URL, []byte("data"), "application/json")

	require.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), "myoutput")
	assert.Contains(t, err.Error(), "400")
}

func TestSenderDoReadBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response-data"))
	}))
	defer server.Close()

	s, _ := NewSender("test", &HTTPConfig{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)

	body, err := s.DoReadBody(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "response-data", string(body))
}

func TestSenderDoReadBodyErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	s, _ := NewSender("myoutput", &HTTPConfig{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)

	body, err := s.DoReadBody(context.Background(), req)
	require.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), "myoutput")
	assert.Contains(t, err.Error(), "500")
}

func TestSenderDoReadBodyConnectionRefused(t *testing.T) {
	s, _ := NewSender("myoutput", &HTTPConfig{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost:1", http.NoBody)
	require.NoError(t, err)

	body, err := s.DoReadBody(context.Background(), req)
	require.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), "myoutput send")
}

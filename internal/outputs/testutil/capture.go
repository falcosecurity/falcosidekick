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

package testutil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// CapturedRequest is one request received by a capture server.
type CapturedRequest struct {
	Header http.Header
	URL    *url.URL
	Method string
	Body   []byte
}

// Recorder answers requests with Status, or StatusByPath for a listed path,
// and Reply, and keeps a copy of each request.
type Recorder struct {
	StatusByPath map[string]int
	Reply        string
	requests     []CapturedRequest
	Status       int
	mu           sync.Mutex
}

// NewRecorder starts a server backed by a Recorder.
func NewRecorder(t *testing.T, status int, reply string) (rec *Recorder, server *httptest.Server) {
	t.Helper()
	rec = &Recorder{Status: status, Reply: reply}
	server = httptest.NewServer(rec)
	t.Cleanup(server.Close)
	return rec, server
}

func (r *Recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.requests = append(r.requests, CapturedRequest{Header: req.Header.Clone(), URL: req.URL, Method: req.Method, Body: body})
	status := r.Status
	if s, ok := r.StatusByPath[req.URL.Path]; ok {
		status = s
	}
	r.mu.Unlock()
	w.WriteHeader(status)
	_, _ = io.WriteString(w, r.Reply)
}

// Received returns a copy of the requests received so far.
func (r *Recorder) Received() []CapturedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]CapturedRequest(nil), r.requests...)
}

// StartCaptureServer answers every request with status and reply and
// sends a copy of each request on the returned channel (buffer of 4).
func StartCaptureServer(t *testing.T, status int, reply string) (server *httptest.Server, received <-chan CapturedRequest) {
	t.Helper()
	requests := make(chan CapturedRequest, 4)
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		requests <- CapturedRequest{Header: r.Header.Clone(), URL: r.URL, Method: r.Method, Body: body}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

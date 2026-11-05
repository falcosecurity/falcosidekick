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

package otlp

import (
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// received holds the OTLP requests a receiver accepted.
type received struct {
	traces    []*coltrace.ExportTraceServiceRequest
	logs      []*collogs.ExportLogsServiceRequest
	metrics   []*colmetrics.ExportMetricsServiceRequest
	headers   []map[string]string
	paths     []string
	encodings []string
}

// receiver records OTLP requests received over HTTP or gRPC.
type receiver struct {
	got received
	// failures is the number of next requests answered with code.
	failures int
	code     int
	mu       sync.Mutex
}

func (r *receiver) fail(n, code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures, r.code = n, code
}

// admit records the request metadata and returns the failure code, if any.
func (r *receiver) admit(path string, headers map[string]string, encoding string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got.headers = append(r.got.headers, headers)
	r.got.paths = append(r.got.paths, path)
	r.got.encodings = append(r.got.encodings, encoding)
	if r.failures > 0 {
		r.failures--
		return r.code
	}
	return 0
}

func (r *receiver) snapshot() *received {
	r.mu.Lock()
	defer r.mu.Unlock()
	got := r.got
	return &got
}

func (r *receiver) store(fn func(got *received)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(&r.got)
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	headers := map[string]string{}
	for name := range req.Header {
		headers[strings.ToLower(name)] = req.Header.Get(name)
	}
	if code := r.admit(req.URL.Path, headers, req.Header.Get("Content-Encoding")); code != 0 {
		w.WriteHeader(code)
		return
	}
	body := io.Reader(req.Body)
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body = gz
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var msg, resp proto.Message
	var keep func(got *received)
	switch {
	case strings.HasSuffix(req.URL.Path, "/traces"):
		m := &coltrace.ExportTraceServiceRequest{}
		msg, resp, keep = m, &coltrace.ExportTraceServiceResponse{}, func(got *received) { got.traces = append(got.traces, m) }
	case strings.HasSuffix(req.URL.Path, "/logs"):
		m := &collogs.ExportLogsServiceRequest{}
		msg, resp, keep = m, &collogs.ExportLogsServiceResponse{}, func(got *received) { got.logs = append(got.logs, m) }
	case strings.HasSuffix(req.URL.Path, "/metrics"):
		m := &colmetrics.ExportMetricsServiceRequest{}
		msg, resp, keep = m, &colmetrics.ExportMetricsServiceResponse{}, func(got *received) { got.metrics = append(got.metrics, m) }
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := proto.Unmarshal(raw, msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.store(keep)
	out, _ := proto.Marshal(resp)
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(out)
}

func (r *receiver) admitGRPC(ctx context.Context, signal string) error {
	md, _ := metadata.FromIncomingContext(ctx)
	headers := map[string]string{}
	for name, values := range md {
		headers[name] = strings.Join(values, ",")
	}
	encoding := ""
	if values := md.Get("grpc-encoding"); len(values) > 0 {
		encoding = values[0]
	}
	if code := r.admit(signal, headers, encoding); code != 0 {
		return status.Error(codes.Code(uint32(code)), "rejected")
	}
	return nil
}

type traceService struct {
	coltrace.UnimplementedTraceServiceServer
	r *receiver
}

func (s traceService) Export(ctx context.Context, req *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	if err := s.r.admitGRPC(ctx, "traces"); err != nil {
		return nil, err
	}
	s.r.store(func(got *received) { got.traces = append(got.traces, req) })
	return &coltrace.ExportTraceServiceResponse{}, nil
}

type logsService struct {
	collogs.UnimplementedLogsServiceServer
	r *receiver
}

func (s logsService) Export(ctx context.Context, req *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	if err := s.r.admitGRPC(ctx, "logs"); err != nil {
		return nil, err
	}
	s.r.store(func(got *received) { got.logs = append(got.logs, req) })
	return &collogs.ExportLogsServiceResponse{}, nil
}

type metricsService struct {
	colmetrics.UnimplementedMetricsServiceServer
	r *receiver
}

func (s metricsService) Export(ctx context.Context, req *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	if err := s.r.admitGRPC(ctx, "metrics"); err != nil {
		return nil, err
	}
	s.r.store(func(got *received) { got.metrics = append(got.metrics, req) })
	return &colmetrics.ExportMetricsServiceResponse{}, nil
}

func startHTTPReceiver(t *testing.T) (r *receiver, endpoint string) {
	t.Helper()
	r = &receiver{}
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return r, server.URL
}

func startGRPCReceiver(t *testing.T) (r *receiver, endpoint string) {
	t.Helper()
	r = &receiver{}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	coltrace.RegisterTraceServiceServer(server, traceService{r: r})
	collogs.RegisterLogsServiceServer(server, logsService{r: r})
	colmetrics.RegisterMetricsServiceServer(server, metricsService{r: r})
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(server.Stop)
	return r, "http://" + ln.Addr().String()
}

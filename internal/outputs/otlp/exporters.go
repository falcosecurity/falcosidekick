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
	"context"
	"crypto/tls"
	"net/http"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// exporterSettings sets every option so OTEL_* variables cannot change it; the pipeline owns retries.
type exporterSettings struct {
	tls        *tls.Config
	httpClient *http.Client
	headers    map[string]string
	cfg        *signalConfig
	target     target
}

func newExporterSettings(cfg *signalConfig, defaultPath string) (*exporterSettings, error) {
	headers, err := cfg.resolveHeaders()
	if err != nil {
		return nil, err
	}
	s := &exporterSettings{cfg: cfg, headers: headers, target: cfg.target(defaultPath)}
	if s.grpc() {
		if s.target.secure {
			s.tls, err = shared.BuildTLSConfig(&cfg.TLS)
		}
		return s, err
	}
	// The shared client applies the redirect policy of every HTTP output.
	var httpCfg shared.HTTPConfig
	if s.target.secure {
		httpCfg.TLS = cfg.TLS
	}
	if s.httpClient, err = shared.BuildHTTPClient(&httpCfg); err != nil {
		return nil, err
	}
	s.httpClient.Timeout = cfg.Timeout
	s.httpClient.Transport = statusRecorder{base: s.httpClient.Transport}
	return s, nil
}

// closeIdleConnections releases the idle connections of the HTTP client; the exporters' Shutdown does not.
func (s *exporterSettings) closeIdleConnections() {
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
}

// recordResult lets newDeliveryError see a gRPC partial success.
var recordResult = grpc.WithUnaryInterceptor(recordPartialSuccess)

func (s *exporterSettings) grpc() bool { return s.cfg.Protocol == protocolGRPC }

func (s *exporterSettings) gzip() bool { return s.cfg.Compression == compressionGzip }

func newSpanExporter(ctx context.Context, s *exporterSettings) (sdktrace.SpanExporter, error) {
	if s.grpc() {
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(s.target.host),
			otlptracegrpc.WithHeaders(s.headers),
			otlptracegrpc.WithTimeout(s.cfg.Timeout),
			otlptracegrpc.WithCompressor(s.cfg.Compression),
			otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}),
			otlptracegrpc.WithDialOption(recordResult),
		}
		if s.target.secure {
			opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(s.tls)))
		} else {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptracegrpc.New(ctx, opts...)
	}
	compression := otlptracehttp.NoCompression
	if s.gzip() {
		compression = otlptracehttp.GzipCompression
	}
	return otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(s.target.url()),
		otlptracehttp.WithTimeout(s.cfg.Timeout),
		otlptracehttp.WithHeaders(s.headers),
		otlptracehttp.WithHTTPClient(s.httpClient),
		otlptracehttp.WithCompression(compression),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
	)
}

func newLogExporter(ctx context.Context, s *exporterSettings) (sdklog.Exporter, error) {
	if s.grpc() {
		opts := []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(s.target.host),
			otlploggrpc.WithHeaders(s.headers),
			otlploggrpc.WithTimeout(s.cfg.Timeout),
			otlploggrpc.WithCompressor(s.cfg.Compression),
			otlploggrpc.WithRetry(otlploggrpc.RetryConfig{Enabled: false}),
			otlploggrpc.WithDialOption(recordResult),
		}
		if s.target.secure {
			opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(s.tls)))
		} else {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, opts...)
	}
	compression := otlploghttp.NoCompression
	if s.gzip() {
		compression = otlploghttp.GzipCompression
	}
	return otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(s.target.url()),
		otlploghttp.WithTimeout(s.cfg.Timeout),
		otlploghttp.WithHeaders(s.headers),
		otlploghttp.WithHTTPClient(s.httpClient),
		otlploghttp.WithCompression(compression),
		otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: false}),
	)
}

func newMetricExporter(ctx context.Context, s *exporterSettings) (sdkmetric.Exporter, error) {
	temporality := otlpmetricgrpc.WithTemporalitySelector(sdkmetric.DefaultTemporalitySelector)
	if s.grpc() {
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(s.target.host),
			otlpmetricgrpc.WithHeaders(s.headers),
			otlpmetricgrpc.WithTimeout(s.cfg.Timeout),
			otlpmetricgrpc.WithCompressor(s.cfg.Compression),
			otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{Enabled: false}),
			otlpmetricgrpc.WithDialOption(recordResult),
			temporality,
		}
		if s.target.secure {
			opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(s.tls)))
		} else {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		return otlpmetricgrpc.New(ctx, opts...)
	}
	compression := otlpmetrichttp.NoCompression
	if s.gzip() {
		compression = otlpmetrichttp.GzipCompression
	}
	return otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(s.target.url()),
		otlpmetrichttp.WithTimeout(s.cfg.Timeout),
		otlpmetrichttp.WithHeaders(s.headers),
		otlpmetrichttp.WithHTTPClient(s.httpClient),
		otlpmetrichttp.WithCompression(compression),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
		otlpmetrichttp.WithTemporalitySelector(sdkmetric.DefaultTemporalitySelector),
	)
}

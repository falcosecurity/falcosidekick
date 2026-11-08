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

package api

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
)

// ServerConfig holds HTTP server dependencies.
type ServerConfig struct {
	Pipeline *pipeline.Pipeline
	Database core.Database
	Catalog  *catalog.Catalog
	Metrics  core.MetricsCollector
	Registry *prometheus.Registry
	Reloader *reload.Reloader // optional; required for UI-driven output mutations
	UIAssets fs.FS            // optional; serves under GET / when non-nil
	Config   *core.Config
	Logger   *slog.Logger
}

// Server manages the Fiber HTTP application.
type Server struct {
	app          *fiber.App
	pipeline     *pipeline.Pipeline
	database     core.Database
	catalog      *catalog.Catalog
	metrics      core.MetricsCollector
	tls          *core.TLSConfig
	reloader     *reload.Reloader
	logger       *slog.Logger
	uiAssets     fs.FS
	address      string
	eventSource  string
	provisioning core.ProvisioningConfig
}

// NewServer creates a Fiber-based HTTP Server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	var tls *core.TLSConfig
	var eventSource string
	var provisioning core.ProvisioningConfig
	address := "0.0.0.0"
	port := 2801

	if cfg.Pipeline == nil {
		return nil, fmt.Errorf("server: pipeline is required")
	}
	if cfg.Catalog == nil {
		return nil, fmt.Errorf("server: catalog is required")
	}
	if cfg.Config != nil {
		tls = cfg.Config.TLS
		eventSource = cfg.Config.UI.EventSource
		provisioning = cfg.Config.Provisioning
		if cfg.Config.ListenAddress != "" {
			address = cfg.Config.ListenAddress
		}
		if cfg.Config.ListenPort != 0 {
			port = cfg.Config.ListenPort
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		pipeline:     cfg.Pipeline,
		database:     cfg.Database,
		catalog:      cfg.Catalog,
		metrics:      cfg.Metrics,
		reloader:     cfg.Reloader,
		uiAssets:     cfg.UIAssets,
		logger:       logger,
		address:      fmt.Sprintf("%s:%d", address, port),
		eventSource:  eventSource,
		provisioning: provisioning,
		tls:          tls,
	}

	s.app = s.mountRoutes(cfg.Registry)
	return s, nil
}

// mountRoutes registers routes with static segments (`/types`, `/status`,
// `/layout`) declared before `:name` so Fiber's matcher prefers literals.
func (s *Server) mountRoutes(registry *prometheus.Registry) *fiber.App {
	app := fiber.New()
	app.Use(recover.New())
	app.Use(compress.New())

	app.Post("/", s.handlePostEvent)
	app.Get("/healthz", s.handleGetHealthz)
	app.Get("/version", s.handleGetVersion)

	v1 := app.Group("/api/v1")

	events := v1.Group("/events")
	events.Get("/search", s.handleEventsSearch)
	events.Get("/count", s.handleEventsCount)
	events.Get("/count/:groupby", s.handleEventsCountBy)
	events.Get("/histogram", s.handleEventsHistogram)
	events.Get("/:uuid", s.handleEventByUUID)

	pipe := v1.Group("/pipeline")
	pipe.Get("", s.handlePipelineComposite)
	pipe.Get("/layout", s.handlePipelineLayout)
	pipe.Get("/status", s.handlePipelineStatus)
	pipe.Get("/status/:name", s.handlePipelineStatusByName)

	pipe.Put("/layout", s.handlePipelineLayoutPut)

	outputs := pipe.Group("/outputs")
	outputs.Get("", s.handlePipelineOutputs)
	outputs.Get("/types", s.handlePipelineOutputTypes)
	outputs.Get("/types/:name", s.handlePipelineOutputTypeByName)
	outputs.Get("/:name", s.handlePipelineOutputByName)
	outputs.Put("/:name", s.handlePipelineOutputPut)
	outputs.Delete("/:name", s.handlePipelineOutputDelete)

	v1.Get("/config", s.handleGetConfig)
	v1.Get("/version", s.handleGetVersion)

	if registry != nil {
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		app.Get("/metrics", adaptor.HTTPHandler(handler))
	}

	registerStaticUI(app, s.uiAssets)

	return app
}

// GetReadableStore resolves the ReadableStore dynamically through the pipeline.
// Returns nil when no event source is configured or the output does not implement ReadableStore.
func (s *Server) GetReadableStore() output.ReadableStore {
	if s.eventSource == "" {
		return nil
	}
	rs, _ := s.pipeline.GetReadableStore(s.eventSource)
	return rs
}

// Start begins listening for HTTP requests. Blocks until the server stops.
// Uses TLS when configured, including mutual TLS with client cert verification.
func (s *Server) Start() error {
	cfg := fiber.ListenConfig{DisableStartupMessage: true}
	if s.tls != nil && s.tls.Enabled {
		cfg.CertFile = s.tls.CertFile
		cfg.CertKeyFile = s.tls.KeyFile
		if s.tls.MutualTLS {
			cfg.CertClientFile = s.tls.CACertFile
		}
	}
	s.logger.Info("listening", "address", s.address, "outputs", s.pipeline.Dispatcher().OutputNames())
	return s.app.Listen(s.address, cfg)
}

// Shutdown gracefully stops the server, bounded by the caller's context.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}

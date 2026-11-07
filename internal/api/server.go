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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"time"

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

// Server serves two listeners: ingestion (Falco events, health, version, metrics), reachable by every
// Falco, and management (the API and the UI), local by default because the API has no authentication.
type Server struct {
	// app serves the management listener.
	app *fiber.App
	// ingestion serves the event listener.
	ingestion *fiber.App
	pipeline  *pipeline.Pipeline
	database  core.Database
	catalog   *catalog.Catalog
	metrics   core.MetricsCollector
	tls       *core.TLSConfig
	// coreConfig is this replica's configuration, served masked by GET /api/v1/config.
	coreConfig        *core.Config
	reloader          *reload.Reloader
	logger            *slog.Logger
	uiAssets          fs.FS
	address           string
	managementAddress string
	eventSource       string
	secretDirs        []string
	provisioning      core.ProvisioningConfig
	allowWrites       bool
}

// NewServer creates the Fiber applications of both listeners.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.Pipeline == nil {
		return nil, fmt.Errorf("server: pipeline is required")
	}
	if cfg.Catalog == nil {
		return nil, fmt.Errorf("server: catalog is required")
	}
	if cfg.Config == nil {
		return nil, fmt.Errorf("server: config is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		pipeline:          cfg.Pipeline,
		database:          cfg.Database,
		catalog:           cfg.Catalog,
		metrics:           cfg.Metrics,
		reloader:          cfg.Reloader,
		uiAssets:          cfg.UIAssets,
		logger:            logger,
		address:           net.JoinHostPort(cfg.Config.ListenAddress, strconv.Itoa(cfg.Config.ListenPort)),
		managementAddress: net.JoinHostPort(cfg.Config.Management.ListenAddress, strconv.Itoa(cfg.Config.Management.ListenPort)),
		eventSource:       cfg.Config.UI.EventSource,
		provisioning:      cfg.Config.Provisioning,
		allowWrites:       cfg.Config.API.AllowWrites,
		secretDirs:        slices.Clone(cfg.Config.API.SecretDirs),
		tls:               cfg.Config.TLS,
		coreConfig:        cfg.Config.DeepCopy(),
	}

	if s.allowWrites && !isLoopback(cfg.Config.Management.ListenAddress) {
		logger.Warn("API writes are enabled without authentication on a non-loopback management address",
			"management_address", cfg.Config.Management.ListenAddress)
	}

	s.ingestion = s.mountIngestion(cfg.Registry)
	s.app = s.mountManagement()
	return s, nil
}

// Connection bounds for slow or idle clients; fasthttp arms the write deadline after the handler
// returns, so a long API write is not cut short.
const (
	readTimeout  = 30 * time.Second
	writeTimeout = 30 * time.Second
	idleTimeout  = 2 * time.Minute
)

func newApp() *fiber.App {
	app := fiber.New(fiber.Config{
		// Request values, such as the :name parameter kept as a map key, are copied out of the
		// connection buffer that fasthttp reuses for the next request.
		Immutable:    true,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	})
	app.Use(recover.New())
	app.Use(compress.New())
	return app
}

// mountIngestion serves what Falco, Kubernetes probes and Prometheus reach from other hosts.
func (s *Server) mountIngestion(registry *prometheus.Registry) *fiber.App {
	app := newApp()
	app.Post("/", s.handlePostEvent)
	app.Get("/healthz", s.handleGetHealthz)
	app.Get("/version", s.handleGetVersion)
	if registry != nil {
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		app.Get("/metrics", adaptor.HTTPHandler(handler))
	}
	return app
}

// mountManagement declares static segments before :name so Fiber matches the literals first.
// /healthz is also here, for a readiness probe on this listener.
func (s *Server) mountManagement() *fiber.App {
	app := newApp()
	app.Get("/healthz", s.handleGetHealthz)

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

	pipe.Put("/layout", s.requireWrites, s.handlePipelineLayoutPut)

	outputs := pipe.Group("/outputs")
	outputs.Get("", s.handlePipelineOutputs)
	outputs.Get("/types", s.handlePipelineOutputTypes)
	outputs.Get("/types/:name", s.handlePipelineOutputTypeByName)
	outputs.Get("/:name", s.handlePipelineOutputByName)
	outputs.Put("/:name", s.requireWrites, s.handlePipelineOutputPut)
	outputs.Delete("/:name", s.requireWrites, s.handlePipelineOutputDelete)

	v1.Get("/config", s.handleGetConfig)
	v1.Get("/version", s.handleGetVersion)

	registerStaticUI(app, s.uiAssets)

	return app
}

// GetReadableStore resolves the event source through the pipeline on each call, or returns nil.
func (s *Server) GetReadableStore() output.ReadableStore {
	if s.eventSource == "" {
		return nil
	}
	rs, _ := s.pipeline.GetReadableStore(s.eventSource)
	return rs
}

// Start listens on both addresses and blocks until one listener stops; TLS applies to both.
func (s *Server) Start() error {
	cfg := fiber.ListenConfig{DisableStartupMessage: true}
	if s.tls != nil && s.tls.Enabled {
		cfg.CertFile = s.tls.CertFile
		cfg.CertKeyFile = s.tls.KeyFile
		if s.tls.MutualTLS {
			cfg.CertClientFile = s.tls.CACertFile
		}
	}
	s.logger.Info("listening", "address", s.address, "management_address", s.managementAddress,
		"outputs", s.pipeline.Dispatcher().OutputNames())
	stopped := make(chan error, 2)
	go func() { stopped <- s.ingestion.Listen(s.address, cfg) }()
	go func() { stopped <- s.app.Listen(s.managementAddress, cfg) }()
	return <-stopped
}

// Shutdown gracefully stops both listeners, bounded by the caller's context.
func (s *Server) Shutdown(ctx context.Context) error {
	return errors.Join(s.ingestion.ShutdownWithContext(ctx), s.app.ShutdownWithContext(ctx))
}

// isLoopback reports whether address only accepts local connections.
func isLoopback(address string) bool {
	if address == "localhost" {
		return true
	}
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}

const errWritesDisabled = "API writes are disabled (set api.allow_writes to enable)"

// requireWrites guards routes that change the running configuration.
func (s *Server) requireWrites(c fiber.Ctx) error {
	if !s.allowWrites {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": errWritesDisabled})
	}
	return c.Next()
}

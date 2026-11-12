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
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
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
	// RuntimeDefaults are the runtime settings each output's own are merged over, served by GET /api/v1/config.
	RuntimeDefaults output.RuntimeConfig
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
	// operations is the parent of every API request context; Shutdown cancels it.
	operations       context.Context
	cancelOperations context.CancelFunc
	// coreConfig is this replica's configuration, served masked by GET /api/v1/config.
	coreConfig        *core.Config
	reloader          *reload.Reloader
	logger            *slog.Logger
	uiAssets          fs.FS
	address           string
	managementAddress string
	eventSource       string
	secretDirs        []string
	runtimeDefaults   output.RuntimeConfig
	provisioning      core.ProvisioningConfig
	allowWrites       bool
	// rejectInlineSecrets refuses API writes with an inline secret, for a persistent database.
	rejectInlineSecrets bool
	// ready is what /readyz reports; see SetReady.
	ready atomic.Bool
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
		pipeline:            cfg.Pipeline,
		database:            cfg.Database,
		catalog:             cfg.Catalog,
		metrics:             cfg.Metrics,
		reloader:            cfg.Reloader,
		uiAssets:            cfg.UIAssets,
		logger:              logger,
		address:             net.JoinHostPort(cfg.Config.ListenAddress, strconv.Itoa(cfg.Config.ListenPort)),
		managementAddress:   net.JoinHostPort(cfg.Config.Management.ListenAddress, strconv.Itoa(cfg.Config.Management.ListenPort)),
		eventSource:         cfg.Config.UI.EventSource,
		provisioning:        cfg.Config.Provisioning,
		allowWrites:         cfg.Config.API.AllowWrites,
		secretDirs:          slices.Clone(cfg.Config.API.SecretDirs),
		tls:                 cfg.Config.TLS,
		coreConfig:          cfg.Config.DeepCopy(),
		runtimeDefaults:     cfg.RuntimeDefaults.DeepCopy(),
		rejectInlineSecrets: cfg.Config.Database.Backend.Persistent(),
	}
	s.operations, s.cancelOperations = context.WithCancel(context.Background())

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

// maxBodySize bounds a request body on both listeners; a larger one is answered 413 before any handler runs.
const maxBodySize = 4 << 20

func newApp(errorHandler fiber.ErrorHandler) *fiber.App {
	app := fiber.New(fiber.Config{
		// Request values, such as the :name parameter kept as a map key, are copied out of the
		// connection buffer that fasthttp reuses for the next request.
		Immutable:    true,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		BodyLimit:    maxBodySize,
		ErrorHandler: errorHandler,
	})
	app.Use(recover.New())
	app.Use(compress.New())
	return app
}

// Probe and scrape routes of the ingestion listener; with mutual TLS they need no client certificate,
// since kubelet probes and most scrapers present none.
const (
	routeIngest  = "/"
	routeLive    = "/livez"
	routeReady   = "/readyz"
	routeMetrics = "/metrics"
)

// mountIngestion serves what Falco, Kubernetes probes and Prometheus reach from other hosts.
func (s *Server) mountIngestion(registry *prometheus.Registry) *fiber.App {
	app := newApp(s.errorHandler(true))
	if s.tls != nil && s.tls.Enabled && s.tls.MutualTLS {
		app.Use(requireClientCertificate)
	}
	app.Post(routeIngest, s.handlePostEvent)
	app.Get(routeLive, s.handleGetLive)
	app.Get(routeReady, s.handleGetReady)
	if registry != nil {
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		app.Get(routeMetrics, adaptor.HTTPHandler(handler))
	}
	return app
}

// requireClientCertificate refuses a request without a verified client certificate, except on the
// probe and scrape routes. The TLS handshake already verified any certificate that was sent.
func requireClientCertificate(c fiber.Ctx) error {
	switch c.Path() {
	case routeLive, routeReady, routeMetrics:
		return c.Next()
	}
	if state := c.RequestCtx().TLSConnectionState(); state == nil || len(state.VerifiedChains) == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "client certificate required"})
	}
	return c.Next()
}

// mountManagement declares static segments before :name so Fiber matches the literals first.
func (s *Server) mountManagement() *fiber.App {
	app := newApp(s.errorHandler(false))

	v1 := app.Group("/api/v1", s.boundOperation)

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
	// The secret listing serves only API writes, so it is off with them.
	v1.Get("/secrets", s.requireWrites, s.handleGetSecrets)
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

// Start listens on both addresses, IPv4 and IPv6, with TLS on both, and blocks until one listener stops. With mutual TLS the management
// listener requires a client certificate in the handshake; ingestion verifies one when sent and requireClientCertificate enforces it per route.
func (s *Server) Start() error {
	management := fiber.ListenConfig{DisableStartupMessage: true, ListenerNetwork: fiber.NetworkTCP}
	if s.tls != nil && s.tls.Enabled {
		management.CertFile = s.tls.CertFile
		management.CertKeyFile = s.tls.KeyFile
		if s.tls.MutualTLS {
			management.CertClientFile = s.tls.CACertFile
		}
	}
	ingestion := management
	if s.tls != nil && s.tls.Enabled && s.tls.MutualTLS {
		ingestion.TLSConfigFunc = func(c *tls.Config) { c.ClientAuth = tls.VerifyClientCertIfGiven }
	}
	s.logger.Info("listening", "address", s.address, "management_address", s.managementAddress,
		"outputs", s.pipeline.Dispatcher().OutputNames())
	stopped := make(chan error, 2)
	go func() { stopped <- s.ingestion.Listen(s.address, ingestion) }()
	go func() { stopped <- s.app.Listen(s.managementAddress, management) }()
	return <-stopped
}

// SetReady sets what /readyz answers: ready once the pipeline runs, not ready from SIGTERM on.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

// Shutdown stops both listeners, bounded by ctx: the management listener first, so no API change starts while ingestion drains. An API
// request still running when ctx ends is canceled, so a database call it waits on returns and the reloader it holds is released.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.app.ShutdownWithContext(ctx)
	s.cancelOperations()
	return errors.Join(err, s.ingestion.ShutdownWithContext(ctx))
}

// apiOperationTimeout bounds an API request, building an output and its database calls included.
const apiOperationTimeout = 30 * time.Second

// boundOperation runs an API request with a deadline, on a context the shutdown cancels.
func (s *Server) boundOperation(c fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(s.operations, apiOperationTimeout)
	defer cancel()
	c.SetContext(ctx)
	return c.Next()
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

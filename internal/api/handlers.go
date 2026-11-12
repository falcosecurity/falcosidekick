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

	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

func (s *Server) handlePostEvent(c fiber.Ctx) error {
	var evt event.Event
	if err := c.Bind().JSON(&evt); err != nil {
		s.recordRequest(core.IngestInvalid)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid JSON",
		})
	}

	if err := evt.Validate(); err != nil {
		s.recordRequest(core.IngestInvalid)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	s.recordRequest(core.IngestAccepted)

	s.pipeline.ProcessEvent(context.Background(), &evt)
	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) recordRequest(status string) {
	if s.metrics != nil {
		s.metrics.RecordRequest(context.Background(), status)
	}
}

// handleGetLive answers while the process serves requests.
func (s *Server) handleGetLive(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}

// handleGetReady answers 503 before the pipeline runs and from SIGTERM on, so Kubernetes routes
// events only to a replica that delivers them.
func (s *Server) handleGetReady(c fiber.Ctx) error {
	if !s.ready.Load() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"status": "not ready"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ready"})
}

func (s *Server) handleGetVersion(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version.GetInfo())
}

// configResponse is the core configuration with the runtime defaults each output's runtime settings
// are merged over.
type configResponse struct {
	*core.Config
	RuntimeDefaults output.RuntimeConfig `json:"runtime_defaults"`
}

// handleGetConfig serves the configuration this replica runs with, durations written as in its files ("30s").
func (s *Server) handleGetConfig(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"config": durationsAsStrings(configResponse{
		Config:          maskCoreConfig(s.coreConfig),
		RuntimeDefaults: s.runtimeDefaults.DeepCopy(),
	})})
}

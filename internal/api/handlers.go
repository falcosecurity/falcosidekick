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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

func (s *Server) handlePostEvent(c fiber.Ctx) error {
	var evt event.Event
	if err := c.Bind().JSON(&evt); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid JSON: " + err.Error(),
		})
	}

	if err := evt.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	if s.metrics != nil {
		s.metrics.RecordInput(context.Background(), evt.Source, "accepted")
	}

	s.pipeline.ProcessEvent(context.Background(), &evt)
	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) handleGetHealthz(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "ok",
	})
}

func (s *Server) handleGetVersion(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version.GetInfo())
}

func (s *Server) handleGetConfig(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "database not configured",
		})
	}

	entry, err := s.database.GetConfig(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "read config: " + err.Error(),
		})
	}
	if entry == nil {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	}

	entry.Config = maskCoreConfig(entry.Config)
	return c.Status(fiber.StatusOK).JSON(entry)
}

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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func (s *Server) handlePipelineStatus(c fiber.Ctx) error {
	statuses := s.pipeline.CollectOutputStatus()
	if statuses == nil {
		statuses = []pipeline.OutputStatus{}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"outputs": statuses})
}

func (s *Server) handlePipelineStatusByName(c fiber.Ctx) error {
	name := c.Params("name")
	statuses := s.pipeline.CollectOutputStatus()
	for i := range statuses {
		st := &statuses[i]
		if st.Name == name {
			return c.Status(fiber.StatusOK).JSON(st)
		}
	}
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output not found"})
}

func (s *Server) handlePipelineOutputs(c fiber.Ctx) error {
	entries, ok := s.loadMaskedOutputs(c)
	if !ok {
		return nil
	}
	return c.Status(fiber.StatusOK).JSON(entries)
}

func (s *Server) handlePipelineOutputByName(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
	}
	name := c.Params("name")
	entry, err := s.database.GetOutputConfig(c.Context(), name)
	if err != nil {
		return s.databaseUnavailable(c, name, err)
	}
	if entry == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output not found"})
	}
	t, _ := s.catalog.Get(name)
	masked := maskOutputConfig(entry, t)
	return c.Status(fiber.StatusOK).JSON(masked)
}

func (s *Server) handlePipelineOutputTypes(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"types": s.catalog.All()})
}

func (s *Server) handlePipelineOutputTypeByName(c fiber.Ctx) error {
	name := c.Params("name")
	t, ok := s.catalog.Get(name)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output type not found"})
	}
	return c.Status(fiber.StatusOK).JSON(t)
}

func (s *Server) handlePipelineLayout(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
	}
	layout, err := s.database.GetPipelineLayout(c.Context())
	if err != nil {
		return s.databaseUnavailable(c, "layout", err)
	}
	if layout == nil {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	}
	return c.Status(fiber.StatusOK).JSON(layout)
}

func (s *Server) handlePipelineComposite(c fiber.Ctx) error {
	outputs, ok := s.loadMaskedOutputs(c)
	if !ok {
		return nil
	}

	statuses := s.pipeline.CollectOutputStatus()
	if statuses == nil {
		statuses = []pipeline.OutputStatus{}
	}

	layout, err := s.database.GetPipelineLayout(c.Context())
	if err != nil {
		return s.databaseUnavailable(c, "layout", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"outputs": outputs,
		"status":  statuses,
		"layout":  layout,
	})
}

func (s *Server) handlePipelineOutputPut(c fiber.Ctx) error {
	name, handled := s.checkMutationPrereqs(c)
	if handled {
		return nil
	}

	t, typeOK := s.catalog.Get(name)
	if !typeOK {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown output type: " + name})
	}

	var body outputPutRequest
	if err := decodeStrict(c.Body(), &body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request: " + err.Error()})
	}
	if body.Config == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "config must be an object"})
	}
	if body.Version == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "version is required: send the version read with GET, or 0 to create the output",
		})
	}

	existing, handled := s.loadOutputEntryForMutation(c, name)
	if handled {
		return nil
	}
	var existingCfg map[string]any
	var existingVersion int64
	if existing != nil {
		existingCfg, existingVersion = existing.Config, existing.Version
	}
	// The merge below starts from this read; the reloader checks the version again under its lock.
	if existingVersion != *body.Version {
		return writeVersionConflict(c, name)
	}

	if field := containsSecretPlaceholder(body.Config, t); field != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "field '" + field + "' is a secret placeholder; omit the key to keep the existing value",
		})
	}
	stored, merged, err := mergeOutputConfigForSchema(existingCfg, body.Config, t.Schema)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if s.rejectInlineSecrets {
		if found := output.InlineSecrets(merged, t.Schema.Fields); len(found) > 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": found[0].String()})
		}
	}
	if err := checkFilePaths(stored, merged, t.Schema.Fields, s.secretDirs); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if t.CheckAPIWrite != nil {
		if err := t.CheckAPIWrite(body.Config); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	version, err := s.reloader.ApplyOutput(c.Context(), name, existingVersion, merged)
	if err != nil {
		return s.writeMutationError(c, name, "apply", err)
	}
	// Answered from what was stored, not read back: a later write may already have replaced it.
	saved := &core.OutputConfigEntry{Name: name, Config: merged, Version: version, UpdatedAt: time.Now().UTC()}
	return c.Status(fiber.StatusOK).JSON(maskOutputConfig(saved, t))
}

// outputPutRequest is the body of PUT /api/v1/pipeline/outputs/:name.
type outputPutRequest struct {
	Config map[string]any `json:"config"`
	// Version is the version read with GET, 0 to create the output.
	Version *int64 `json:"version"`
}

// decodeStrict decodes one JSON value and rejects unknown fields and trailing data.
// Its errors never quote the body, field names included.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return errors.New("unknown field")
		}
		return errors.New("invalid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

func writeVersionConflict(c fiber.Ctx, name string) error {
	return c.Status(fiber.StatusConflict).JSON(fiber.Map{
		"error": "output '" + name + "' changed since the version sent; read it again and retry",
	})
}

func (s *Server) handlePipelineOutputDelete(c fiber.Ctx) error {
	name, handled := s.checkMutationPrereqs(c)
	if handled {
		return nil
	}

	version, err := strconv.ParseInt(c.Query("version"), 10, 64)
	if err != nil || version < 1 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "version is required: send ?version= with the version read with GET"})
	}

	entry, handled := s.loadOutputEntryForMutation(c, name)
	if handled {
		return nil
	}
	if entry == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output '" + name + "' not found"})
	}
	if entry.Version != version {
		return writeVersionConflict(c, name)
	}

	if err := s.reloader.RemoveOutput(c.Context(), name, version); err != nil {
		return s.writeMutationError(c, name, "remove", err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) handlePipelineLayoutPut(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
	}

	var layout core.PipelineLayout
	if err := decodeStrict(c.Body(), &layout); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request: " + err.Error()})
	}

	if err := s.database.SavePipelineLayout(c.Context(), &layout); err != nil {
		return s.databaseUnavailable(c, "layout", err)
	}
	layout.UpdatedAt = time.Now().UTC()
	return c.Status(fiber.StatusOK).JSON(layout)
}

// loadMaskedOutputs writes 503 or 500 and returns false when the database is missing or fails.
func (s *Server) loadMaskedOutputs(c fiber.Ctx) (map[string]*outputConfigResponse, bool) {
	if s.database == nil {
		_ = c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
		return nil, false
	}
	entries, err := s.database.GetOutputConfigs(c.Context())
	if err != nil {
		_ = s.databaseUnavailable(c, "outputs", err)
		return nil, false
	}
	return maskOutputConfigs(entries, s.catalog), true
}

// checkMutationPrereqs returns handled=true once it has written the error response.
func (s *Server) checkMutationPrereqs(c fiber.Ctx) (name string, handled bool) {
	if s.reloader == nil {
		_ = c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "reloader not configured"})
		return "", true
	}
	if s.database == nil {
		_ = c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
		return "", true
	}
	name = c.Params("name")
	if name == "" {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "output name is required"})
		return "", true
	}
	return name, false
}

// loadOutputEntryForMutation answers 409 for a provisioned entry unless UI updates are allowed.
func (s *Server) loadOutputEntryForMutation(c fiber.Ctx, name string) (entry *core.OutputConfigEntry, handled bool) {
	entry, err := s.database.GetOutputConfig(c.Context(), name)
	if err != nil {
		_ = s.databaseUnavailable(c, name, err)
		return nil, true
	}
	if entry != nil && entry.Provisioned && !s.provisioning.AllowUIUpdates {
		_ = c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "output '" + name + "' is file-provisioned; UI updates are disabled (set provisioning.allow_ui_updates to allow)",
		})
		return nil, true
	}
	return entry, false
}

// databaseUnavailable answers 503 for a database failure; the error, which can carry server text,
// is logged and never sent.
func (s *Server) databaseUnavailable(c fiber.Ctx, subject string, err error) error {
	s.logger.Error("database request failed", "subject", subject, "error", err)
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database unavailable"})
}

func (s *Server) writeMutationError(c fiber.Ctx, name, verb string, err error) error {
	switch {
	case errors.Is(err, pipeline.ErrDispatcherStopped):
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "dispatcher stopped"})
	case errors.Is(err, reload.ErrReloaderClosed):
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "shutting down: output '" + name + "' was not changed"})
	case errors.Is(err, reload.ErrReloaderNotBound):
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "reloader not bound"})
	case errors.Is(err, core.ErrVersionConflict):
		return writeVersionConflict(c, name)
	case errors.Is(err, pipeline.ErrInvalidOutputConfig):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": verb + " output: " + err.Error()})
	case errors.Is(err, reload.ErrDatabaseUnavailable):
		return s.databaseUnavailable(c, name, err)
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": verb + " output: " + err.Error()})
	}
}

// mergeOutputConfig deep-merges patch into a copy of existing so keys absent from a PUT keep their stored value.
func mergeOutputConfig(existing, patch map[string]any) map[string]any {
	result := utils.DeepCopyMap(existing)
	if result == nil {
		result = make(map[string]any, len(patch))
	}
	utils.DeepMergeMap(result, utils.DeepCopyMap(patch))
	return result
}

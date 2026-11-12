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
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Phases of a refused output change: validation, the driver build, or the database. A destination
// that fails its probe never refuses a change.
const (
	phaseValidate = pipeline.PhaseValidate
	phaseStore    = "store"
)

// errInternal answers a recovered panic or an unexpected error; the cause is logged, never sent.
const errInternal = "internal error; see the falcosidekick log"

// fieldError is one refused setting; path is the schema key relative to the output's config, such as tls.ca_file.
type fieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// errorResponse is the body of every API error; phase and fields are set for a refused output change only.
type errorResponse struct {
	Error  string       `json:"error"`
	Phase  string       `json:"phase,omitempty"`
	Fields []fieldError `json:"fields,omitempty"`
}

func writeChangeError(c fiber.Ctx, status int, phase, summary string, err error) error {
	return c.Status(status).JSON(errorResponse{Error: summary, Phase: phase, Fields: fieldErrors(err)})
}

// fieldErrors returns the field errors of every utils.ValidationErrors in err's chain; a fieldless error stays in the summary.
func fieldErrors(err error) []fieldError {
	var fields []fieldError
	var walk func(error)
	walk = func(err error) {
		switch e := err.(type) {
		case nil:
		case utils.ValidationErrors:
			for _, ve := range e {
				if ve.Field != "" {
					fields = append(fields, fieldError{Path: ve.Field, Message: ve.Message})
				}
			}
		case utils.ValidationError:
			if e.Field != "" {
				fields = append(fields, fieldError{Path: e.Field, Message: e.Message})
			}
		case interface{ Unwrap() []error }:
			for _, child := range e.Unwrap() {
				walk(child)
			}
		default:
			walk(errors.Unwrap(err))
		}
	}
	walk(err)
	return fields
}

// errorHandler answers a recovered panic or an unexpected error with the fixed errInternal and a Fiber
// error with its status text; an oversized body on the ingestion route counts as an invalid ingest request.
func (s *Server) errorHandler(ingestion bool) fiber.ErrorHandler {
	return func(c fiber.Ctx, err error) error {
		if fiberErr, ok := errors.AsType[*fiber.Error](err); ok {
			if ingestion && fiberErr.Code == fiber.StatusRequestEntityTooLarge &&
				c.Method() == fiber.MethodPost && c.Path() == routeIngest {
				s.recordRequest(core.IngestInvalid)
			}
			return c.Status(fiberErr.Code).JSON(errorResponse{Error: http.StatusText(fiberErr.Code)})
		}
		s.logger.Error("request failed", "method", c.Method(), "path", c.Path(), "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{Error: errInternal})
	}
}

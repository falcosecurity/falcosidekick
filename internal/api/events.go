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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseFilters(c fiber.Ctx) (*output.Filters, error) {
	f := &output.Filters{
		Filter:   c.Query("filter"),
		Priority: splitCSV(c.Query("priority")),
		Rule:     splitCSV(c.Query("rule")),
		Source:   splitCSV(c.Query("source")),
		Hostname: splitCSV(c.Query("hostname")),
		Tags:     splitCSV(c.Query("tags")),
	}
	if raw := c.Query("since"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid since: %w", err)
		}
		if d < 0 {
			return nil, fmt.Errorf("invalid since: must be non-negative, got %s", d)
		}
		f.Since = d
	}
	return f, nil
}

func parseSearchQuery(c fiber.Ctx) (*output.SearchQuery, error) {
	f, err := parseFilters(c)
	if err != nil {
		return nil, err
	}
	q := &output.SearchQuery{
		Filters: *f,
	}
	if raw := c.Query("page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid page: %w", err)
		}
		q.Page = n
	}
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid limit: %w", err)
		}
		q.Limit = n
	}
	if raw := c.Query("sort_by"); raw != "" {
		q.SortBy = raw
	}
	if raw := c.Query("sort_desc"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid sort_desc: %w", err)
		}
		q.SortDesc = b
	}
	if err := q.Normalize(); err != nil {
		return nil, err
	}
	return q, nil
}

// readableStoreOrUnavailable writes 503 and returns (nil, false) when
// the configured event source is not resolvable; caller must return nil.
func (s *Server) readableStoreOrUnavailable(c fiber.Ctx) (output.ReadableStore, bool) {
	rs := s.GetReadableStore()
	if rs == nil {
		_ = c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "event store not available",
		})
		return nil, false
	}
	return rs, true
}

func (s *Server) handleEventsSearch(c fiber.Ctx) error {
	rs, ok := s.readableStoreOrUnavailable(c)
	if !ok {
		return nil
	}
	q, err := parseSearchQuery(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	result, err := rs.Search(c.Context(), q)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (s *Server) handleEventsCount(c fiber.Ctx) error {
	rs, ok := s.readableStoreOrUnavailable(c)
	if !ok {
		return nil
	}
	f, err := parseFilters(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	n, err := rs.Count(c.Context(), f)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"count": n})
}

func (s *Server) handleEventsCountBy(c fiber.Ctx) error {
	rs, ok := s.readableStoreOrUnavailable(c)
	if !ok {
		return nil
	}
	field := c.Params("groupby")
	if err := output.ValidateGroupBy(field); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	f, err := parseFilters(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	groups, err := rs.CountBy(c.Context(), field, f)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if groups == nil {
		groups = map[string]int64{}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"groups": groups})
}

func (s *Server) handleEventsHistogram(c fiber.Ctx) error {
	rs, ok := s.readableStoreOrUnavailable(c)
	if !ok {
		return nil
	}
	f, err := parseFilters(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	raw := c.Query("bucket_ms")
	if raw == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "bucket_ms is required"})
	}
	bucketMs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid bucket_ms: %v", err)})
	}
	req := &output.HistogramRequest{
		Filters:  *f,
		BucketMs: bucketMs,
		GroupBy:  c.Query("group_by"),
	}
	if err := req.Normalize(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	res, err := rs.Histogram(c.Context(), req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(res)
}

func (s *Server) handleEventByUUID(c fiber.Ctx) error {
	rs, ok := s.readableStoreOrUnavailable(c)
	if !ok {
		return nil
	}
	uuid := c.Params("uuid")
	evt, err := rs.GetEvent(c.Context(), uuid)
	if err != nil {
		if errors.Is(err, output.ErrEmptyUUID) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if evt == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "event not found"})
	}
	return c.Status(fiber.StatusOK).JSON(evt)
}

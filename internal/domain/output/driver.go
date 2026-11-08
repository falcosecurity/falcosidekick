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

package output

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// Driver represents the send implementation for one output type.
type Driver interface {
	Name() string
	Init(ctx context.Context) error
	Send(ctx context.Context, evt *event.Event) error
	HealthCheck(ctx context.Context) error
	RuntimeConfig() RuntimeConfig
	Close() error
}

// BatchSender is an optional interface for outputs that support batch delivery.
// The dispatcher checks for this at startup. Batching activates only when both
// the output implements BatchSender and batching is enabled in config.
type BatchSender interface {
	SendBatch(ctx context.Context, events []*event.Event) error
}

// ErrEmptyUUID indicates an empty UUID passed to GetEvent.
var ErrEmptyUUID = errors.New("uuid is required")

// ReadableStore is an optional interface for outputs that support event queries.
// The API layer uses this to serve the UI. Only outputs configured as the
// ui.event_source need to implement it (e.g., inmemory, redis, postgres).
//
// Filter combination semantics are part of the contract:
//   - Within a single field, multiple values combine with OR
//     (e.g. Filters{Priority: ["critical","error"]} matches events whose
//     priority is critical OR error).
//   - Across fields, criteria combine with AND
//     (e.g. Filters{Priority: ["critical"], Rule: ["foo"]} matches events
//     whose priority is critical AND rule is foo).
//   - Since is applied as AND alongside the structured filters.
//   - SearchQuery.Filter (free text) is applied as AND as a case-insensitive
//     substring match over output, rule, priority, source, hostname, and tags.
//
// GetEvent lookup semantics:
//   - A hit returns the event and a nil error.
//   - A miss returns (nil, nil); callers map this to 404.
//   - An empty uuid returns (nil, ErrEmptyUUID); callers map this to 400.
//   - Any other error indicates a lookup failure; callers map this to 500.
type ReadableStore interface {
	Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)
	Count(ctx context.Context, filters *Filters) (int64, error)
	CountBy(ctx context.Context, field string, filters *Filters) (map[string]int64, error)
	Histogram(ctx context.Context, req *HistogramRequest) (*HistogramResult, error)
	GetEvent(ctx context.Context, uuid string) (*event.Event, error)
}

// HistogramRequest describes a time-bucketed aggregation over the event store.
// Filters.Since defines the window (must be > 0). BucketMs is the bucket width
// in milliseconds. GroupBy is optional; when set, each bucket carries per-group
// counts in addition to the total. Callers must invoke Normalize.
type HistogramRequest struct {
	GroupBy  string  `json:"group_by,omitempty"`
	Filters  Filters `json:"filters"`
	BucketMs int64   `json:"bucket_ms"`
}

// HistogramBucket is one time slice of the histogram. T is the bucket start
// expressed as Unix milliseconds. By is non-nil only when GroupBy was set;
// it is sparse, containing only groups with at least one event in the bucket.
type HistogramBucket struct {
	By    map[string]int64 `json:"by,omitempty"`
	T     int64            `json:"t"`
	Count int64            `json:"count"`
}

// HistogramResult is a dense series of buckets spanning [From, To). The first
// bucket starts at From; the last bucket ends at To. Consumers can render the
// slice directly without gap-filling.
type HistogramResult struct {
	GroupBy  string            `json:"group_by,omitempty"`
	Buckets  []HistogramBucket `json:"buckets"`
	BucketMs int64             `json:"bucket_ms"`
	From     int64             `json:"from"`
	To       int64             `json:"to"`
}

const (
	histogramMinBucket = time.Second
	histogramMaxBucket = 24 * time.Hour
	histogramMaxCount  = 1024
)

// Normalize validates the request and rejects inputs that would generate an
// unbounded or malformed histogram.
func (r *HistogramRequest) Normalize() error {
	if r.Filters.Since <= 0 {
		return fmt.Errorf("histogram: since must be > 0")
	}
	if r.BucketMs <= 0 {
		return fmt.Errorf("histogram: bucket_ms must be > 0")
	}
	if r.BucketMs < histogramMinBucket.Milliseconds() {
		return fmt.Errorf("histogram: bucket_ms must be >= %s", histogramMinBucket)
	}
	if r.BucketMs > histogramMaxBucket.Milliseconds() {
		return fmt.Errorf("histogram: bucket_ms must be <= %s", histogramMaxBucket)
	}
	bucket := time.Duration(r.BucketMs) * time.Millisecond
	if r.Filters.Since < bucket {
		return fmt.Errorf("histogram: since must be >= bucket_ms")
	}
	buckets := int64(r.Filters.Since / bucket)
	if r.Filters.Since%bucket != 0 {
		buckets++
	}
	if buckets > histogramMaxCount {
		return fmt.Errorf("histogram: window produces %d buckets, max is %d", buckets, histogramMaxCount)
	}
	if r.GroupBy != "" {
		if err := ValidateGroupBy(r.GroupBy); err != nil {
			return fmt.Errorf("histogram: %w", err)
		}
	}
	return nil
}

// Type describes an available output kind.
type Type struct {
	New      func(cfg map[string]any, deps Deps) (Driver, error) `json:"-"`
	Name     string                                              `json:"name"`
	Category string                                              `json:"category"`
	Schema   Schema                                              `json:"schema"`
}

// Deps holds shared dependencies injected into outputs at creation.
type Deps struct {
	Logger  *slog.Logger
	Metrics core.MetricsCollector
}

// Schema describes configuration fields for an output type.
type Schema struct {
	Fields []SchemaField `json:"fields"`
}

// SchemaField describes a single configuration parameter.
type SchemaField struct {
	// EntryFields describes the properties of each value in a map field.
	EntryFields []SchemaField `json:"entry_fields,omitempty"`
	Default     any           `json:"default,omitempty"`
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Label       string        `json:"label"`
	Values      []string      `json:"values,omitempty"`
	Required    bool          `json:"required"`
	Secret      bool          `json:"secret,omitempty"`
}

// SearchQuery holds parameters for querying stored events.
// The free-text search term lives on Filters.Filter so that Search, Count,
// and CountBy all honor it uniformly through a single *Filters value.
type SearchQuery struct {
	SortBy   string  `json:"sort_by"`
	Filters  Filters `json:"filters"`
	Page     int     `json:"page"`
	Limit    int     `json:"limit"`
	SortDesc bool    `json:"sort_desc"`
}

// Filters holds filter criteria for event queries. Filter is a free-text
// case-insensitive substring match applied across output, rule, priority,
// source, hostname, and tags. All filter fields combine as AND across
// fields and as OR within each multi-value field.
type Filters struct {
	Filter   string        `json:"filter,omitempty"`
	Priority []string      `json:"priority,omitempty"`
	Rule     []string      `json:"rule,omitempty"`
	Source   []string      `json:"source,omitempty"`
	Hostname []string      `json:"hostname,omitempty"`
	Tags     []string      `json:"tags,omitempty"`
	Since    time.Duration `json:"since,omitempty"`
}

// SearchResult holds a page of events with pagination metadata.
type SearchResult struct {
	Events []event.Event `json:"events"`
	Total  int64         `json:"total"`
	Page   int           `json:"page"`
	Limit  int           `json:"limit"`
}

// Normalize applies defaults and validates the query.
// Default sort is timestamp descending (newest first).
func (q *SearchQuery) Normalize() error {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 10000 {
		q.Limit = 10000
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.SortBy == "" {
		q.SortBy = "timestamp"
		q.SortDesc = true
	}
	if !validSortFields[q.SortBy] {
		return fmt.Errorf("search: invalid sort_by %q", q.SortBy)
	}
	return nil
}

var validSortFields = map[string]bool{
	"timestamp": true, "priority": true, "rule": true, "source": true,
}

// ValidateGroupBy checks if a field is allowed for CountBy aggregation.
func ValidateGroupBy(field string) error {
	if !validGroupByFields[field] {
		return fmt.Errorf("invalid group_by field: %q", field)
	}
	return nil
}

var validGroupByFields = map[string]bool{
	"priority": true, "rule": true, "source": true, "tags": true, "hostname": true,
}

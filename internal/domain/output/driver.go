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
type BatchSender interface {
	SendBatch(ctx context.Context, events []*event.Event) error
}

// LateFailureReporter is an optional interface for drivers that learn of a failed delivery after Send returned.
// The handler is installed before the first Send and is called once per failed event, from any goroutine.
type LateFailureReporter interface {
	SetLateFailureHandler(handler func(err error))
}

// WarningReporter is an optional interface for drivers that deliver while part of the destination fails.
// The handler is installed before the first Send; an empty string clears the warning.
type WarningReporter interface {
	SetWarningHandler(handler func(warning string))
}

// ErrMisconfigured marks a HealthCheck failure that a retry cannot fix, so the configuration is refused.
var ErrMisconfigured = errors.New("destination rejects the configuration")

// ErrPermanent marks a delivery failure that a retry cannot fix.
var ErrPermanent = errors.New("destination rejects the delivery")

// IsPermanent reports whether retrying err cannot succeed.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent) || errors.Is(err, ErrMisconfigured)
}

// ErrEmptyUUID indicates an empty UUID passed to GetEvent.
var ErrEmptyUUID = errors.New("uuid is required")

// ReadableStore is an optional interface for outputs that serve event queries to the UI.
// GetEvent returns (nil, nil) on a miss and ErrEmptyUUID for an empty uuid.
type ReadableStore interface {
	Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)
	Count(ctx context.Context, filters *Filters) (int64, error)
	CountBy(ctx context.Context, field string, filters *Filters) (map[string]int64, error)
	Histogram(ctx context.Context, req *HistogramRequest) (*HistogramResult, error)
	GetEvent(ctx context.Context, uuid string) (*event.Event, error)
}

// HistogramRequest describes a time-bucketed aggregation; callers must invoke Normalize.
type HistogramRequest struct {
	GroupBy  string  `json:"group_by,omitempty"`
	Filters  Filters `json:"filters"`
	BucketMs int64   `json:"bucket_ms"`
}

// HistogramBucket is one time slice starting at T (Unix ms); By lists only non-empty groups.
type HistogramBucket struct {
	By    map[string]int64 `json:"by,omitempty"`
	T     int64            `json:"t"`
	Count int64            `json:"count"`
}

// HistogramResult is a dense, gap-free series of buckets spanning [From, To).
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

// Normalize rejects requests that would produce an unbounded or malformed histogram.
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
	New func(cfg map[string]any, deps Deps) (Driver, error) `json:"-"`
	// CheckAPIWrite, when set, refuses values an API write sends that only an output file may hold,
	// such as settings that make the output read local resources. patch has the request's key spelling.
	CheckAPIWrite func(patch map[string]any) error `json:"-"`
	Name          string                           `json:"name"`
	Category      Category                         `json:"category"`
	Schema        Schema                           `json:"schema"`
	// EventSource marks a type whose driver implements ReadableStore, so ui.event_source may name it.
	EventSource bool `json:"event_source"`
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
	// File marks a path, or a list of paths, the output reads; secret strings take theirs as <name>_file.
	File bool `json:"file,omitempty"`
}

// HasFileVariant reports whether the field also accepts <name>_file, the path of a file holding the value.
func (f *SchemaField) HasFileVariant() bool { return f.Secret && f.Type == "string" }

// IsMap reports whether the field holds an object keyed by names, such as headers.
func (f *SchemaField) IsMap() bool { return f != nil && (f.Type == "map" || len(f.EntryFields) > 0) }

// SearchQuery holds parameters for querying stored events.
type SearchQuery struct {
	SortBy   string  `json:"sort_by"`
	Filters  Filters `json:"filters"`
	Page     int     `json:"page"`
	Limit    int     `json:"limit"`
	SortDesc bool    `json:"sort_desc"`
}

// Filters holds event query criteria, combined with AND across fields and OR within a field.
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
		return errors.New("search: sort_by must be timestamp/priority/rule/source")
	}
	return nil
}

var validSortFields = map[string]bool{
	"timestamp": true, "priority": true, "rule": true, "source": true,
}

// ValidateGroupBy checks if a field is allowed for CountBy aggregation.
func ValidateGroupBy(field string) error {
	if !validGroupByFields[field] {
		return errors.New("group_by must be priority/rule/source/tags/hostname")
	}
	return nil
}

var validGroupByFields = map[string]bool{
	"priority": true, "rule": true, "source": true, "tags": true, "hostname": true,
}

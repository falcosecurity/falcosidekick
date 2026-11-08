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
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchQueryNormalize(t *testing.T) {
	tests := []struct {
		name      string
		wantSort  string
		query     SearchQuery
		wantLimit int
		wantPage  int
		wantErr   bool
	}{
		{
			name:      "defaults applied",
			query:     SearchQuery{},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "zero limit defaults to 100",
			query:     SearchQuery{Limit: 0},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "negative limit defaults to 100",
			query:     SearchQuery{Limit: -5},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "limit preserved under cap",
			query:     SearchQuery{Limit: 5000},
			wantLimit: 5000, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "limit capped at 10000",
			query:     SearchQuery{Limit: 50000},
			wantLimit: 10000, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "negative page defaults to 1",
			query:     SearchQuery{Page: -1},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "valid sort by priority",
			query:     SearchQuery{SortBy: "priority"},
			wantLimit: 100, wantPage: 1, wantSort: "priority",
		},
		{
			name:      "valid sort by rule",
			query:     SearchQuery{SortBy: "rule"},
			wantLimit: 100, wantPage: 1, wantSort: "rule",
		},
		{
			name:    "invalid sort field",
			query:   SearchQuery{SortBy: "invalid_field"},
			wantErr: true,
		},
		{
			name:      "preserves valid values",
			query:     SearchQuery{Limit: 50, Page: 3, SortBy: "source"},
			wantLimit: 50, wantPage: 3, wantSort: "source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Normalize()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantLimit, tt.query.Limit)
			assert.Equal(t, tt.wantPage, tt.query.Page)
			assert.Equal(t, tt.wantSort, tt.query.SortBy)
		})
	}
}

func TestHistogramRequestNormalize(t *testing.T) {
	baseFilters := Filters{Since: 24 * time.Hour}
	tests := []struct {
		wantErr string
		name    string
		req     HistogramRequest
	}{
		{
			name: "valid minimal",
			req:  HistogramRequest{Filters: Filters{Since: 24 * time.Hour}, BucketMs: (15 * time.Minute).Milliseconds()},
		},
		{
			name: "valid with group_by",
			req:  HistogramRequest{Filters: baseFilters, BucketMs: (15 * time.Minute).Milliseconds(), GroupBy: "source"},
		},
		{
			name: "minimum bucket inclusive",
			req:  HistogramRequest{Filters: Filters{Since: time.Second}, BucketMs: time.Second.Milliseconds()},
		},
		{
			name: "maximum bucket inclusive",
			req:  HistogramRequest{Filters: baseFilters, BucketMs: (24 * time.Hour).Milliseconds()},
		},
		{
			name: "maximum bucket count inclusive",
			req:  HistogramRequest{Filters: Filters{Since: 1024 * time.Second}, BucketMs: time.Second.Milliseconds()},
		},
		{
			name:    "partial bucket exceeds maximum count",
			req:     HistogramRequest{Filters: Filters{Since: 1024*time.Second + time.Nanosecond}, BucketMs: time.Second.Milliseconds()},
			wantErr: "max is 1024",
		},
		{
			name:    "bucket duration overflow wraps into valid range",
			req:     HistogramRequest{Filters: Filters{Since: time.Hour}, BucketMs: 18_446_744_133_710},
			wantErr: "bucket_ms must be <= 24h0m0s",
		},
		{
			name:    "maximum integer bucket",
			req:     HistogramRequest{Filters: baseFilters, BucketMs: math.MaxInt64},
			wantErr: "bucket_ms must be <= 24h0m0s",
		},
		{
			name:    "zero since",
			req:     HistogramRequest{BucketMs: 60_000},
			wantErr: "since must be > 0",
		},
		{
			name:    "zero bucket_ms",
			req:     HistogramRequest{Filters: baseFilters},
			wantErr: "bucket_ms must be > 0",
		},
		{
			name:    "bucket_ms below minimum",
			req:     HistogramRequest{Filters: baseFilters, BucketMs: 100},
			wantErr: "bucket_ms must be >= 1s",
		},
		{
			name:    "bucket_ms above maximum",
			req:     HistogramRequest{Filters: Filters{Since: 48 * time.Hour}, BucketMs: (25 * time.Hour).Milliseconds()},
			wantErr: "bucket_ms must be <= 24h0m0s",
		},
		{
			name:    "since smaller than bucket",
			req:     HistogramRequest{Filters: Filters{Since: time.Minute}, BucketMs: (5 * time.Minute).Milliseconds()},
			wantErr: "since must be >= bucket_ms",
		},
		{
			name:    "too many buckets",
			req:     HistogramRequest{Filters: Filters{Since: 24 * time.Hour}, BucketMs: time.Second.Milliseconds()},
			wantErr: "max is 1024",
		},
		{
			name:    "invalid group_by",
			req:     HistogramRequest{Filters: baseFilters, BucketMs: (15 * time.Minute).Milliseconds(), GroupBy: "uuid"},
			wantErr: "invalid group_by",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Normalize()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestValidateGroupBy(t *testing.T) {
	tests := []struct {
		field   string
		wantErr bool
	}{
		{"priority", false},
		{"rule", false},
		{"source", false},
		{"tags", false},
		{"hostname", false},
		{"invalid", true},
		{"", true},
		{"uuid", true},
		{"output", true},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			err := ValidateGroupBy(tt.field)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

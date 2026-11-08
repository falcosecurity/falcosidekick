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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationErrorFormat(t *testing.T) {
	err := ValidationError{Field: "port", Message: "must be > 0"}
	assert.Equal(t, "port: must be > 0", err.Error())
}

func TestValidationErrorsFormat(t *testing.T) {
	var errs ValidationErrors
	errs.Add("port", "must be > 0")
	errs.Add("host", "required")

	got := errs.Error()
	assert.Equal(t, "port: must be > 0; host: required", got)
}

func TestValidationErrorsFormatEdgeCases(t *testing.T) {
	assert.Empty(t, ValidationErrors(nil).Error())
	assert.Equal(t, "port: bad", ValidationErrors{{Field: "port", Message: "bad"}}.Error())
}

func TestValidationErrorsAdd(t *testing.T) {
	var errs ValidationErrors
	assert.Empty(t, errs)

	errs.Add("field", "bad")
	assert.Len(t, errs, 1)
	assert.Equal(t, "field", errs[0].Field)
	assert.Equal(t, "bad", errs[0].Message)
}

func TestValidationErrorsMerge(t *testing.T) {
	var parent ValidationErrors
	var child ValidationErrors
	child.Add("max", "too high")
	child.Add("min", "too low")

	parent.Merge("retry", child)

	assert.Len(t, parent, 2)
	assert.Equal(t, "retry.max", parent[0].Field)
	assert.Equal(t, "retry.min", parent[1].Field)
}

func TestValidationErrorsMergeEmptyPrefix(t *testing.T) {
	var parent ValidationErrors
	var child ValidationErrors
	child.Add("queue_size", "must be > 0")

	parent.Merge("", child)

	assert.Len(t, parent, 1)
	assert.Equal(t, "queue_size", parent[0].Field)
}

func TestValidationErrorsMergeFieldFormatting(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		field  string
		want   string
	}{
		{name: "prefix and field", prefix: "tls", field: "cert", want: "tls.cert: bad"},
		{name: "prefix only", prefix: "url", field: "", want: "url: bad"},
		{name: "field only", prefix: "", field: "cert", want: "cert: bad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var parent ValidationErrors
			parent.Merge(tc.prefix, ValidationErrors{{Field: tc.field, Message: "bad"}})
			assert.Equal(t, tc.want, parent.Error())
		})
	}
}

func TestValidationErrorsMergeNilChild(t *testing.T) {
	var parent ValidationErrors
	parent.Merge("prefix", nil)

	assert.Empty(t, parent)
}

func TestValidationErrorsNilIsEmpty(t *testing.T) {
	var errs ValidationErrors
	assert.Nil(t, errs)
	assert.Empty(t, errs)
	assert.Len(t, errs, 0)
}

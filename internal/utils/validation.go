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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// ValidationError represents a single field validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Message)
}

// ValidationErrors collects multiple validation failures.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	messages := make([]string, len(ve))
	for i, err := range ve {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

// Add appends a validation error for the given field.
func (ve *ValidationErrors) Add(field, msg string) {
	*ve = append(*ve, ValidationError{Field: field, Message: msg})
}

// CheckFile adds an error for field when path cannot be stat'ed.
// The message names neither the path nor the OS error, which can disclose the file system layout.
func (ve *ValidationErrors) CheckFile(field, path string) {
	switch _, err := os.Stat(path); {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		ve.Add(field, "file does not exist")
	default:
		ve.Add(field, "cannot access file")
	}
}

// Merge appends nested errors with an optional field prefix.
func (ve *ValidationErrors) Merge(prefix string, nested ValidationErrors) {
	for _, err := range nested {
		field := err.Field
		switch {
		case prefix == "":
		case field == "":
			field = prefix
		default:
			field = prefix + "." + field
		}
		ve.Add(field, err.Message)
	}
}

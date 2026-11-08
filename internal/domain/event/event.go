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

package event

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// ErrInvalidEvent indicates a malformed event.
var ErrInvalidEvent = errors.New("invalid event")

// Priority represents a Falco event severity level.
type Priority string

// Priority constants ordered by severity (lowest to highest).
const (
	PriorityDebug         Priority = "debug"
	PriorityInformational Priority = "informational"
	PriorityNotice        Priority = "notice"
	PriorityWarning       Priority = "warning"
	PriorityError         Priority = "error"
	PriorityCritical      Priority = "critical"
	PriorityAlert         Priority = "alert"
	PriorityEmergency     Priority = "emergency"
)

var priorityOrder = map[Priority]int{
	PriorityDebug:         0,
	PriorityInformational: 1,
	PriorityNotice:        2,
	PriorityWarning:       3,
	PriorityError:         4,
	PriorityCritical:      5,
	PriorityAlert:         6,
	PriorityEmergency:     7,
}

var allPriorities = map[Priority]bool{
	PriorityDebug: true, PriorityInformational: true, PriorityNotice: true,
	PriorityWarning: true, PriorityError: true, PriorityCritical: true,
	PriorityAlert: true, PriorityEmergency: true,
}

// GTE reports whether p is greater than or equal to other in severity.
func (p Priority) GTE(other Priority) bool {
	return priorityOrder[p] >= priorityOrder[other]
}

// Order returns the numeric severity order (0=lowest, 7=highest).
func (p Priority) Order() int {
	return priorityOrder[p]
}

// String returns the priority as a title-cased display string.
func (p Priority) String() string {
	s := string(p)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ParsePriority converts a case-insensitive string to a Priority; "info" is Falco's short form of
// informational.
func ParsePriority(s string) (Priority, error) {
	p := Priority(strings.ToLower(strings.TrimSpace(s)))
	if p == "info" {
		p = PriorityInformational
	}
	if p == "" {
		return "", fmt.Errorf("empty priority")
	}
	if !allPriorities[p] {
		return "", errors.New("unknown priority")
	}
	return p, nil
}

// MarshalText writes the priority as Falco does, such as "Warning", so the event JSON that outputs
// forward and the API serves keeps Falco's shape.
func (p Priority) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// UnmarshalText accepts any casing; Event.Validate refuses an unknown value with its own message.
func (p *Priority) UnmarshalText(text []byte) error {
	if parsed, err := ParsePriority(string(text)); err == nil {
		*p = parsed
		return nil
	}
	*p = Priority(text)
	return nil
}

// Event represents a Falco security event.
type Event struct {
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
	UUID         string                 `json:"uuid,omitempty"`
	Output       string                 `json:"output"`
	Rule         string                 `json:"rule"`
	Source       string                 `json:"source"`
	Hostname     string                 `json:"hostname,omitempty"`
	Priority     Priority               `json:"priority"`
	Tags         []string               `json:"tags,omitempty"`
}

// Clone returns a copy of e that shares no map or slice with it.
func (e *Event) Clone() *Event {
	cp := *e
	cp.OutputFields = utils.DeepCopyMap(e.OutputFields)
	cp.Tags = slices.Clone(e.Tags)
	return &cp
}

// Validate checks required fields and applies defaults.
func (e *Event) Validate() error {
	if e.Rule == "" {
		return fmt.Errorf("%w: rule is required", ErrInvalidEvent)
	}
	if e.Time.IsZero() {
		return fmt.Errorf("%w: time is required", ErrInvalidEvent)
	}
	normalized, err := ParsePriority(string(e.Priority))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	e.Priority = normalized
	// Falco leaves output_fields out with json_include_output_fields_property: false.
	if e.OutputFields == nil {
		e.OutputFields = map[string]any{}
	}
	if e.Source == "" {
		e.Source = "syscall"
	}
	return nil
}

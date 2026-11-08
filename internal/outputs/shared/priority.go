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

package shared

import (
	"fmt"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// Tone is the band of a priority color, for clients that offer named styles instead of colors.
type Tone int

// Tones in rising severity.
const (
	ToneNeutral Tone = iota
	ToneInfo
	ToneWarning
	ToneDanger
)

type paletteEntry struct {
	rgb  int
	tone Tone
}

// palette rises with severity: grey, blues, yellow, orange, then reds that darken up to emergency.
var palette = map[event.Priority]paletteEntry{
	event.PriorityDebug:         {rgb: 0x9e9e9e, tone: ToneNeutral},
	event.PriorityInformational: {rgb: 0x68c2ff, tone: ToneInfo},
	event.PriorityNotice:        {rgb: 0x1e88e5, tone: ToneInfo},
	event.PriorityWarning:       {rgb: 0xffc700, tone: ToneWarning},
	event.PriorityError:         {rgb: 0xff8c00, tone: ToneWarning},
	event.PriorityCritical:      {rgb: 0xf4511e, tone: ToneDanger},
	event.PriorityAlert:         {rgb: 0xd50000, tone: ToneDanger},
	event.PriorityEmergency:     {rgb: 0x8b0000, tone: ToneDanger},
}

// paletteFor returns the entry of p in any casing; an unknown priority gets the debug entry.
func paletteFor(p event.Priority) paletteEntry {
	if e, ok := palette[event.Priority(strings.ToLower(string(p)))]; ok {
		return e
	}
	return palette[event.PriorityDebug]
}

// PriorityRGB returns the color of a priority as a 0xRRGGBB integer.
func PriorityRGB(p event.Priority) int { return paletteFor(p).rgb }

// PriorityColor returns the color of a priority as a "#rrggbb" hex code.
func PriorityColor(p event.Priority) string { return fmt.Sprintf("#%06x", paletteFor(p).rgb) }

// PriorityTone returns the band of the color of a priority.
func PriorityTone(p event.Priority) Tone { return paletteFor(p).tone }

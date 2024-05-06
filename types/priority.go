// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"encoding/json"
	"strings"
)

type PriorityType int

const (
	Default = iota // ""
	Debug
	Informational
	Notice
	Warning
	Error
	Critical
	Alert
	Emergency
)

func (p PriorityType) String() string {
	switch p {
	case Default:
		return ""
	case Debug:
		return "Debug"
	case Informational:
		return "Informational"
	case Notice:
		return "Notice"
	case Warning:
		return "Warning"
	case Error:
		return "Error"
	case Critical:
		return "Critical"
	case Alert:
		return "Alert"
	case Emergency:
		return "Emergency"
	default:
		return ""
	}
}

func Priority(p string) PriorityType {
	switch strings.ToLower(p) {
	case "emergency":
		return Emergency
	case "alert":
		return Alert
	case "critical":
		return Critical
	case "error":
		return Error
	case "warning":
		return Warning
	case "notice":
		return Notice
	case "informational":
		return Informational
	case "info":
		return Informational
	case "debug":
		return Debug
	default:
		return Default
	}
}

func (p *PriorityType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "emergency":
		*p = Emergency
	case "alert":
		*p = Alert
	case "critical":
		*p = Critical
	case "error":
		*p = Error
	case "warning":
		*p = Warning
	case "notice":
		*p = Notice
	case "informational":
		*p = Informational
	case "info":
		*p = Informational
	case "debug":
		*p = Debug
	default:
		*p = Default
	}

	return nil
}

func (p PriorityType) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

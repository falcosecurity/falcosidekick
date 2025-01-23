// SPDX-License-Identifier: MIT OR Apache-2.0

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

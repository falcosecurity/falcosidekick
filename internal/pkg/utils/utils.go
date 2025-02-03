// SPDX-License-Identifier: MIT OR Apache-2.0

package utils

import "log"

const (
	InfoLvl       string = "info"
	InfoPrefix    string = "[INFO] "
	ErrorLvl      string = "error"
	ErrorPrefix   string = "[ERROR]"
	DebugLvl      string = "debug"
	DebugPrefix   string = "[DEBUG]"
	WarningLvl    string = "warning"
	WarningPrefix string = "[WARN] "
	FatalLvl      string = "fatal"
	FatalPrefix   string = "[FATAL]"
)

func Log(level, output, msg string) {
	var prefix string
	switch level {
	case InfoLvl:
		prefix = InfoPrefix
	case ErrorLvl:
		prefix = ErrorPrefix
	case DebugLvl:
		prefix = DebugPrefix
	case WarningLvl:
		prefix = WarningPrefix
	}
	if output != "" {
		log.Printf("%v : %v - %v", prefix, output, msg)
	} else {
		log.Printf("%v : %v", prefix, msg)
	}
}

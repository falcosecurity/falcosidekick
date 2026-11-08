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

package syslog

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

const (
	appName  = "falco"
	nilValue = "-"
	// rfc5424Time is RFC 3339 with at most six fractional digits (RFC 5424 section 6.2.3).
	rfc5424Time = "2006-01-02T15:04:05.000000Z07:00"
	// maxHostname is the HOSTNAME length limit of RFC 5424 section 6.2.4.
	maxHostname = 255

	// cefMaxMessage is the length of the CEF msg key.
	cefMaxMessage = 1023
	// cefCustomStrings is the number of CEF custom string keys, cs1 to cs6.
	cefCustomStrings = 6
	// cefVendorPrefix starts vendor keys, which CEF names after the vendor and the product.
	cefVendorPrefix = "FalcoFalcosidekick"
	cefTagsKey      = cefVendorPrefix + "Tags"
)

// RFC 5424 section 6.2.1 numerical codes.
var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

var severities = map[event.Priority]int{
	event.PriorityEmergency:     0,
	event.PriorityAlert:         1,
	event.PriorityCritical:      2,
	event.PriorityError:         3,
	event.PriorityWarning:       4,
	event.PriorityNotice:        5,
	event.PriorityInformational: 6,
	event.PriorityDebug:         7,
}

var cefSeverities = map[event.Priority]string{
	event.PriorityDebug:         "0",
	event.PriorityInformational: "3",
	event.PriorityNotice:        "4",
	event.PriorityWarning:       "6",
	event.PriorityError:         "7",
	event.PriorityCritical:      "8",
	event.PriorityAlert:         "9",
	event.PriorityEmergency:     "10",
}

var (
	cefHeaderEscaper    = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ")
	cefExtensionEscaper = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`)
)

// severity returns the RFC 5424 severity of a Falco priority.
func severity(p event.Priority) int {
	if s, ok := severities[p]; ok {
		return s
	}
	return severities[event.PriorityNotice]
}

// validHostname reports whether s fits the RFC 5424 HOSTNAME grammar.
func validHostname(s string) bool {
	if s == "" || len(s) > maxHostname {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// message frames stream transports with the octet count: RFC 6587 section 3.4.1, RFC 5425 section 4.3.
func (d *driver) message(evt *event.Event) ([]byte, error) {
	body, err := d.body(evt)
	if err != nil {
		return nil, err
	}
	hostname := evt.Hostname
	if !validHostname(hostname) {
		hostname = d.localHostname
	}
	header := fmt.Sprintf("<%d>1 %s %s %s %s %s %s ",
		d.facility*8+severity(evt.Priority),
		evt.Time.UTC().Format(rfc5424Time),
		hostname, appName, nilValue, nilValue, nilValue)
	msg := make([]byte, 0, len(header)+len(body))
	msg = append(append(msg, header...), body...)
	if d.cfg.Protocol == protocolUDP {
		return msg, nil
	}
	framed := make([]byte, 0, len(msg)+8)
	framed = strconv.AppendInt(framed, int64(len(msg)), 10)
	framed = append(framed, ' ')
	return append(framed, msg...), nil
}

func (d *driver) body(evt *event.Event) ([]byte, error) {
	if d.cfg.Format == formatCEF {
		return []byte(cefBody(evt)), nil
	}
	return json.Marshal(evt)
}

// cefBody renders the event in ArcSight CEF: the rule is the event class ID and name, the output fields
// fill the custom strings cs1 to cs6 in key order and the rest go in vendor keys, which receivers keep
// but cannot search.
func cefBody(evt *event.Event) string {
	extension := make([]string, 0, 6+2*len(evt.OutputFields))
	add := func(key, value string) {
		extension = append(extension, key+"="+cefExtensionEscaper.Replace(value))
	}
	add("rt", strconv.FormatInt(evt.Time.UnixMilli(), 10))
	if evt.Hostname != "" {
		add("dvchost", evt.Hostname)
	}
	add("msg", truncateRunes(evt.Output, cefMaxMessage))
	if evt.UUID != "" {
		add("externalId", evt.UUID)
	}
	if evt.Source != "" {
		add("cat", evt.Source)
	}
	used := map[string]bool{cefTagsKey: true}
	if len(evt.Tags) > 0 {
		add(cefTagsKey, strings.Join(evt.Tags, ","))
	}
	for i, key := range shared.SortMapKeys(evt.OutputFields) {
		value := fmt.Sprint(evt.OutputFields[key])
		if i < cefCustomStrings {
			n := strconv.Itoa(i + 1)
			add("cs"+n+"Label", key)
			add("cs"+n, value)
			continue
		}
		add(cefVendorKey(key, used), value)
	}
	rule := cefHeaderEscaper.Replace(evt.Rule)
	return "CEF:0|Falcosecurity|Falcosidekick|" + cefHeaderEscaper.Replace(version.Version) + "|" + rule + "|" + rule + "|" +
		cefSeverities[evt.Priority] + "|" + strings.Join(extension, " ")
}

// cefVendorKey turns an output field name into a CEF key, such as proc.aname[2] into FalcoFalcosidekickProcAname2:
// letters and digits only, each run capitalized. A key already used gets a numeric suffix.
func cefVendorKey(field string, used map[string]bool) string {
	b := []byte(cefVendorPrefix)
	start := true
	for i := 0; i < len(field); i++ {
		c := field[i]
		switch {
		case c >= 'a' && c <= 'z':
			if start {
				c -= 'a' - 'A'
			}
			b = append(b, c)
			start = false
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b = append(b, c)
			start = false
		default:
			start = true
		}
	}
	base := string(b)
	key := base
	for n := 2; used[key]; n++ {
		key = base + strconv.Itoa(n)
	}
	used[key] = true
	return key
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

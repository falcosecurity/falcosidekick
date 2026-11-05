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

package awssns

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

const (
	dataTypeString = "String"
	dataTypeNumber = "Number"

	maxNumber   = 1e9
	maxDecimals = 5
)

// attributeName matches the SNS message attribute name rules:
// https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
var attributeName = regexp.MustCompile(`^[A-Za-z0-9_-]([A-Za-z0-9_.-]{0,254}[A-Za-z0-9_-])?$`)

// fieldName maps an output field name to an attribute name: proc.aname[2]
// becomes proc.aname.2.
var fieldName = strings.NewReplacer("]", "", "[", ".")

// messageAttributes returns priority, rule, source, tags (comma separated)
// and hostname, then every output field with a string or numeric value. A
// number outside the SNS Number range is sent as a String. An
// output field with the name of a fixed attribute replaces it. Names SNS
// rejects and empty values are left out.
func messageAttributes(evt *event.Event) map[string]snstypes.MessageAttributeValue {
	attrs := make(map[string]snstypes.MessageAttributeValue, len(evt.OutputFields)+5)
	add := func(name, dataType, value string) {
		if value == "" || !validAttributeName(name) {
			return
		}
		attrs[name] = snstypes.MessageAttributeValue{DataType: sdkaws.String(dataType), StringValue: sdkaws.String(value)}
	}
	add("priority", dataTypeString, evt.Priority.String())
	add("rule", dataTypeString, evt.Rule)
	add("source", dataTypeString, evt.Source)
	add("tags", dataTypeString, strings.Join(evt.Tags, ","))
	add("hostname", dataTypeString, evt.Hostname)
	for key, value := range evt.OutputFields {
		name := fieldName.Replace(key)
		switch v := value.(type) {
		case string:
			add(name, dataTypeString, v)
		case json.Number:
			add(name, numberType(v.String()), v.String())
		case float64:
			s := strconv.FormatFloat(v, 'f', -1, 64)
			add(name, numberType(s), s)
		case int:
			s := strconv.Itoa(v)
			add(name, numberType(s), s)
		case int64:
			s := strconv.FormatInt(v, 10)
			add(name, numberType(s), s)
		}
	}
	return attrs
}

// numberType returns Number for values SNS accepts as numbers, from -10^9
// to 10^9 with at most 5 decimals, and String for any other number, such as
// an inode or a nanosecond timestamp.
func numberType(value string) string {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(f) || math.Abs(f) > maxNumber {
		return dataTypeString
	}
	if _, decimals, ok := strings.Cut(value, "."); ok && len(decimals) > maxDecimals {
		return dataTypeString
	}
	if strings.ContainsAny(value, "eE") {
		return dataTypeString
	}
	return dataTypeNumber
}

func validAttributeName(name string) bool {
	lower := strings.ToLower(name)
	return attributeName.MatchString(name) && !strings.Contains(name, "..") &&
		!strings.HasPrefix(lower, "aws.") && !strings.HasPrefix(lower, "amazon.")
}

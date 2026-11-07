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
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	dataTypeString = "String"
	dataTypeNumber = "Number"

	maxNumber   = 1e9
	maxDecimals = 5
)

// attributeName follows https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
var attributeName = regexp.MustCompile(`^[A-Za-z0-9_-]([A-Za-z0-9_.-]{0,254}[A-Za-z0-9_-])?$`)

// fieldName maps proc.aname[2] to proc.aname.2, a valid attribute name.
var fieldName = strings.NewReplacer("]", "", "[", ".")

// maxMessageAttributes is the SQS limit: raw delivery to SQS drops a message with more attributes.
const maxMessageAttributes = 10

// eventAttributes are the event fields message_attributes can name; any other name is an output field.
var eventAttributes = map[string]func(*event.Event) string{
	"priority": func(e *event.Event) string { return e.Priority.String() },
	"rule":     func(e *event.Event) string { return e.Rule },
	"source":   func(e *event.Event) string { return e.Source },
	"tags":     func(e *event.Event) string { return strings.Join(e.Tags, ",") },
	"hostname": func(e *event.Event) string { return e.Hostname },
}

var defaultMessageAttributes = []string{"priority", "rule", "source", "tags", "hostname"}

// validateMessageAttributes refuses names SNS rejects and two names that become the same attribute.
func validateMessageAttributes(names []string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if len(names) > maxMessageAttributes {
		errs.Add("message_attributes", fmt.Sprintf("at most %d: raw delivery to SQS drops a message with more", maxMessageAttributes))
	}
	seen := make(map[string]string, len(names))
	for _, field := range names {
		attribute := fieldName.Replace(field)
		if !validAttributeName(attribute) {
			errs.Add("message_attributes", fmt.Sprintf("%q is not a valid SNS attribute name", field))
			continue
		}
		if previous, ok := seen[attribute]; ok {
			errs.Add("message_attributes", fmt.Sprintf("%q and %q are the same attribute", previous, field))
			continue
		}
		seen[attribute] = field
	}
	return errs
}

// messageAttributes sends the configured attributes the event has, leaving out empty values.
func messageAttributes(evt *event.Event, names []string) map[string]snstypes.MessageAttributeValue {
	attrs := make(map[string]snstypes.MessageAttributeValue, len(names))
	add := func(name, dataType, value string) {
		if value != "" {
			attrs[name] = snstypes.MessageAttributeValue{DataType: sdkaws.String(dataType), StringValue: sdkaws.String(value)}
		}
	}
	for _, key := range names {
		if value, ok := eventAttributes[key]; ok {
			add(key, dataTypeString, value(evt))
			continue
		}
		name := fieldName.Replace(key)
		switch v := evt.OutputFields[key].(type) {
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

// numberType returns String for numbers outside the SNS Number range: -10^9 to 10^9, 5 decimals.
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

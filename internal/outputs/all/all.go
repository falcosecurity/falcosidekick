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

// Package all lists the available output types.
package all

import (
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/alertmanager"
	"github.com/falcosecurity/falcosidekick/internal/outputs/awss3"
	"github.com/falcosecurity/falcosidekick/internal/outputs/awssns"
	"github.com/falcosecurity/falcosidekick/internal/outputs/awssqs"
	"github.com/falcosecurity/falcosidekick/internal/outputs/cloudevents"
	"github.com/falcosecurity/falcosidekick/internal/outputs/datadog"
	"github.com/falcosecurity/falcosidekick/internal/outputs/discord"
	"github.com/falcosecurity/falcosidekick/internal/outputs/elasticsearch"
	"github.com/falcosecurity/falcosidekick/internal/outputs/gcppubsub"
	"github.com/falcosecurity/falcosidekick/internal/outputs/grafanaoncall"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/kafka"
	"github.com/falcosecurity/falcosidekick/internal/outputs/loki"
	"github.com/falcosecurity/falcosidekick/internal/outputs/opsgenie"
	"github.com/falcosecurity/falcosidekick/internal/outputs/otlp"
	"github.com/falcosecurity/falcosidekick/internal/outputs/pagerduty"
	"github.com/falcosecurity/falcosidekick/internal/outputs/policyreport"
	"github.com/falcosecurity/falcosidekick/internal/outputs/redis"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/smtp"
	"github.com/falcosecurity/falcosidekick/internal/outputs/syslog"
	"github.com/falcosecurity/falcosidekick/internal/outputs/talon"
	"github.com/falcosecurity/falcosidekick/internal/outputs/teams"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

// Types returns all registered output types.
func Types() []output.Type {
	return []output.Type{
		alertmanager.OutputType,
		awss3.OutputType,
		awssns.OutputType,
		awssqs.OutputType,
		cloudevents.OutputType,
		datadog.OutputType,
		discord.OutputType,
		elasticsearch.OutputType,
		gcppubsub.OutputType,
		grafanaoncall.OutputType,
		kafka.OutputType,
		loki.OutputType,
		inmemory.OutputType,
		opsgenie.OutputType,
		otlp.OutputType,
		pagerduty.OutputType,
		policyreport.OutputType,
		redis.OutputType,
		slack.OutputType,
		smtp.OutputType,
		syslog.OutputType,
		talon.OutputType,
		teams.OutputType,
		webhook.OutputType,
	}
}

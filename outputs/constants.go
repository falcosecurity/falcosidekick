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

package outputs

const (
	OK            string = "ok"
	Warning       string = "warning"
	Alert         string = "alert"
	Error         string = "error"
	Critical      string = "critical"
	Emergency     string = "emergency"
	Notice        string = "notice"
	Informational string = "informational"
	Debug         string = "debug"
	Info          string = "info"
	None          string = "none"

	All      string = "all"
	Fields   string = "fields"
	Total    string = "total"
	Rejected string = "rejected"
	Accepted string = "accepted"
	Outputs  string = "outputs"

	Rule      string = "rule"
	Priority  string = "priority"
	Source    string = "source"
	Tags      string = "tags"
	Time      string = "time"
	Text      string = "text"
	Plaintext string = "plaintext"
	JSON      string = "json"
	Markdown  string = "markdown"
	Hostname  string = "hostname"

	DefaultFooter  string = "https://github.com/falcosecurity/falcosidekick"
	DefaultIconURL string = "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png"

	// Colors
	PaleCyan  string = "#ccfff2"
	Yellow    string = "#ffc700"
	Red       string = "#e20b0b"
	LigthBlue string = "#68c2ff"
	Lightcyan string = "#5bffb5"
	Orange    string = "#ff5400"

	Kubeless string = "Kubeless"
	Openfaas string = "OpenFaas"
	Fission  string = "Fission"
	Falco    string = "Falco"
	MQTT     string = "MQTT"

	UDP string = "udp"
	TCP string = "tcp"

	// SASL Auth mechanisms for SMTP
	Plain       string = "plain"
	OAuthBearer string = "oauthbearer"
	External    string = "external"
	Anonymous   string = "anonymous"
)

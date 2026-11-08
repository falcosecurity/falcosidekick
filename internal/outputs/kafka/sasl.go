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

package kafka

import (
	"fmt"
	"strings"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func resolveSASL(cfg *config) (kgo.Opt, error) {
	switch strings.ToLower(cfg.Auth.SASL) {
	case "plain":
		return kgo.SASL(plain.Auth{
			User: cfg.Auth.Username,
			Pass: cfg.Auth.Password,
		}.AsMechanism()), nil
	case "scram_sha256":
		return kgo.SASL(scram.Auth{
			User: cfg.Auth.Username,
			Pass: cfg.Auth.Password,
		}.AsSha256Mechanism()), nil
	case "scram_sha512":
		return kgo.SASL(scram.Auth{
			User: cfg.Auth.Username,
			Pass: cfg.Auth.Password,
		}.AsSha512Mechanism()), nil
	case "", configNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("kafka: unsupported SASL mechanism %q", cfg.Auth.SASL)
	}
}

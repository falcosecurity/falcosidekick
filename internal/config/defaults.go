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

package config

import (
	"time"

	"github.com/spf13/viper"
)

func applyDefaults(v *viper.Viper) {
	v.SetDefault("listen_address", "0.0.0.0")
	v.SetDefault("listen_port", 2801)
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "text")

	v.SetDefault("ui.enabled", false)
	v.SetDefault("ui.event_source", "inmemory")

	v.SetDefault("database.backend", "inmemory")

	v.SetDefault("runtime_defaults.queue_size", 1000)
	v.SetDefault("runtime_defaults.workers", 2)

	v.SetDefault("runtime_defaults.retry.max_attempts", 3)
	v.SetDefault("runtime_defaults.retry.initial_interval", time.Second)
	v.SetDefault("runtime_defaults.retry.max_interval", 30*time.Second)
	v.SetDefault("runtime_defaults.retry.multiplier", 2.0)

	v.SetDefault("runtime_defaults.circuit_breaker.failure_threshold", 5)
	v.SetDefault("runtime_defaults.circuit_breaker.success_threshold", 2)
	v.SetDefault("runtime_defaults.circuit_breaker.reset_timeout", 30*time.Second)

	v.SetDefault("runtime_defaults.batching.enabled", false)
	v.SetDefault("runtime_defaults.batching.batch_size", 500)
	v.SetDefault("runtime_defaults.batching.flush_interval", time.Second)

	v.SetDefault("enricher.truncate_event_threshold", 4096)
	v.SetDefault("enricher.truncate_field_threshold", 512)

	v.SetDefault("reload.poll_interval", 30*time.Second)
	v.SetDefault("reload.retire_timeout", 10*time.Second)
}

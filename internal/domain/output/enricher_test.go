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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnricherConfigValidateValid(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateNegativeEventThreshold(t *testing.T) {
	cfg := EnricherConfig{TruncateEventThreshold: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateTooSmallFieldThreshold(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 3,
	}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateDisabledTruncation(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 0,
		TruncateFieldThreshold: 0,
	}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateZeroThresholds(t *testing.T) {
	cfg := EnricherConfig{}
	assert.Empty(t, cfg.Validate())
}

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

package shared

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/backoff"
)

func TestGRPCReconnectParamsKeepTheDefaultsBelowTheCap(t *testing.T) {
	assert.Equal(t, 15*time.Second, GRPCReconnectParams.Backoff.MaxDelay)
	assert.Equal(t, backoff.DefaultConfig.BaseDelay, GRPCReconnectParams.Backoff.BaseDelay)
	assert.InDelta(t, backoff.DefaultConfig.Multiplier, GRPCReconnectParams.Backoff.Multiplier, 0)
	assert.InDelta(t, backoff.DefaultConfig.Jitter, GRPCReconnectParams.Backoff.Jitter, 0)
	assert.Equal(t, 20*time.Second, GRPCReconnectParams.MinConnectTimeout, "grpc-go applies a zero MinConnectTimeout as is")
	assert.NotNil(t, GRPCReconnect)
}

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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
)

// GRPCReconnectMaxDelay caps the wait between gRPC reconnection attempts. The grpc-go default, 120s,
// leaves a destination that came back unused for up to two minutes; 15s is below the circuit reset timeout.
const GRPCReconnectMaxDelay = 15 * time.Second

// GRPCReconnectParams are the grpc-go defaults with the reconnection backoff capped at GRPCReconnectMaxDelay.
var GRPCReconnectParams = func() grpc.ConnectParams {
	b := backoff.DefaultConfig
	b.MaxDelay = GRPCReconnectMaxDelay
	// grpc-go uses MinConnectTimeout as given, so the default 20s is set explicitly.
	return grpc.ConnectParams{Backoff: b, MinConnectTimeout: 20 * time.Second}
}()

// GRPCReconnect is the dial option every gRPC output passes.
var GRPCReconnect = grpc.WithConnectParams(GRPCReconnectParams)

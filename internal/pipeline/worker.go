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

package pipeline

import (
	"context"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// runWorker delivers one event at a time; while the circuit is open a worker holds its event
// in executeWithRetry and takes no other, so the queue waits for the destination.
func (o *Output) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-o.queue:
			if !ok {
				return
			}
			if ctx.Err() != nil {
				o.recordDrop()
				return
			}
			o.executeWithRetry(ctx, []*event.Event{evt}, func(ctx context.Context, events []*event.Event) error {
				return o.driver.Send(ctx, events[0])
			})
		}
	}
}

// runBatchWorker collects up to batch_size events; while the circuit is open it holds that batch
// in executeWithRetry and takes no other.
func (o *Output) runBatchWorker(ctx context.Context) {
	batchCfg := o.config.Batching
	buffer := make([]*event.Event, 0, batchCfg.BatchSize)
	ticker := time.NewTicker(batchCfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.flushBatch(ctx, buffer)
			return
		case <-ticker.C:
			buffer = o.flushBatch(ctx, buffer)
		case evt, ok := <-o.queue:
			if !ok {
				o.flushBatch(ctx, buffer)
				return
			}
			if ctx.Err() != nil {
				o.recordDrop()
				o.flushBatch(ctx, buffer)
				return
			}
			buffer = append(buffer, evt)
			if len(buffer) >= batchCfg.BatchSize {
				buffer = o.flushBatch(ctx, buffer)
				ticker.Reset(batchCfg.FlushInterval)
			}
		}
	}
}

func (o *Output) flushBatch(ctx context.Context, buffer []*event.Event) []*event.Event {
	if len(buffer) == 0 {
		return buffer[:0]
	}

	snapshot := make([]*event.Event, len(buffer))
	copy(snapshot, buffer)

	o.executeWithRetry(ctx, snapshot, func(ctx context.Context, events []*event.Event) error {
		return o.batchSender.SendBatch(ctx, events)
	})

	return buffer[:0]
}

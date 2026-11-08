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
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const configNone = "none"

func buildClientOpts(cfg *config, logger *slog.Logger) ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.RecordDeliveryTimeout(cfg.Producer.DeliveryTimeout),
		kgo.WithLogger(clientLogger{logger: logger}),
	}

	if cfg.Producer.TopicCreation {
		opts = append(opts, kgo.AllowAutoTopicCreation())
	}
	if cfg.Producer.ClientID != "" {
		opts = append(opts, kgo.ClientID(cfg.Producer.ClientID))
	}

	acks := resolveACKs(cfg.Producer.RequiredACKs)
	opts = append(opts, kgo.RequiredAcks(acks))
	opts = append(opts, resolveCompression(cfg.Producer.Compression)...)
	// The default partitioner hashes keyed records with murmur2, as the Java client does, and spreads
	// keyless ones by batch size (KIP-794), so a key always picks the partition.

	if cfg.TLSEnabled {
		tlsCfg, err := shared.BuildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("%s tls: %w", name, err)
		}
		opts = append(opts, kgo.DialTLSConfig(tlsCfg))
	}

	saslOpt, err := resolveSASL(cfg)
	if err != nil {
		return nil, err
	}
	if saslOpt != nil {
		opts = append(opts, saslOpt)
	}

	// Idempotent writes require acks=all. With them the client keeps a record it already sent until
	// the broker answers, so a canceled delivery cannot be reported as failed after it was written.
	if acks != kgo.AllISRAcks() {
		opts = append(opts, kgo.DisableIdempotentWrite())
	}

	return opts, nil
}

func resolveACKs(acks string) kgo.Acks {
	switch strings.ToLower(acks) {
	case configNone:
		return kgo.NoAck()
	case "one":
		return kgo.LeaderAck()
	default:
		return kgo.AllISRAcks()
	}
}

func resolveCompression(c string) []kgo.Opt {
	switch strings.ToLower(c) {
	case "gzip":
		return []kgo.Opt{kgo.ProducerBatchCompression(kgo.GzipCompression())}
	case "snappy":
		return []kgo.Opt{kgo.ProducerBatchCompression(kgo.SnappyCompression())}
	case "lz4":
		return []kgo.Opt{kgo.ProducerBatchCompression(kgo.Lz4Compression())}
	case "zstd":
		return []kgo.Opt{kgo.ProducerBatchCompression(kgo.ZstdCompression())}
	default:
		return []kgo.Opt{kgo.ProducerBatchCompression(kgo.NoCompression())}
	}
}

// clientLogger forwards franz-go warnings and errors, such as dial, TLS and SASL failures.
type clientLogger struct {
	logger *slog.Logger
}

func (clientLogger) Level() kgo.LogLevel { return kgo.LogLevelWarn }

// logFields are the franz-go fields that identify a broker, topic, partition or group.
var logFields = map[string]bool{"broker": true, "addr": true, "topic": true, "topic_id": true, "partition": true, "group": true}

// Log forwards franz-go messages with errors reduced to their diagnostic and only the identifying fields:
// other values, such as requests, can carry broker text.
func (l clientLogger) Log(level kgo.LogLevel, msg string, keyvals ...any) {
	safe := make([]any, 0, len(keyvals))
	for i := 0; i+1 < len(keyvals); i += 2 {
		key, _ := keyvals[i].(string)
		if err, ok := keyvals[i+1].(error); ok {
			safe = append(safe, key, newDeliveryError(opClient, err))
		} else if logFields[key] {
			safe = append(safe, key, keyvals[i+1])
		}
	}
	l.logger.Log(context.Background(), slogLevel(level), msg, safe...)
}

func slogLevel(level kgo.LogLevel) slog.Level {
	switch level {
	case kgo.LogLevelError:
		return slog.LevelError
	case kgo.LogLevelWarn:
		return slog.LevelWarn
	case kgo.LogLevelInfo:
		return slog.LevelInfo
	default:
		return slog.LevelDebug
	}
}

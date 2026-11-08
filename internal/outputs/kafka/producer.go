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

	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const configNone = "none"

func buildClientOpts(cfg *config) ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
	}

	if cfg.Producer.TopicCreation {
		opts = append(opts, kgo.AllowAutoTopicCreation())
	}
	if cfg.Producer.ClientID != "" {
		opts = append(opts, kgo.ClientID(cfg.Producer.ClientID))
	}

	opts = append(opts, kgo.RequiredAcks(resolveACKs(cfg.Producer.RequiredACKs)))
	opts = append(opts, resolveCompression(cfg.Producer.Compression)...)
	opts = append(opts, resolveBalancer(cfg.Producer.Balancer)...)

	if cfg.TLSEnabled {
		tlsCfg, err := shared.BuildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("kafka tls: %w", err)
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

	if cfg.Producer.Async {
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

func resolveBalancer(b string) []kgo.Opt {
	switch strings.ToLower(b) {
	case "round_robin":
		return []kgo.Opt{kgo.RecordPartitioner(kgo.RoundRobinPartitioner())}
	case "least_backup":
		return []kgo.Opt{kgo.RecordPartitioner(kgo.LeastBackupPartitioner())}
	case "sticky":
		return []kgo.Opt{kgo.RecordPartitioner(kgo.StickyPartitioner())}
	default:
		return nil
	}
}

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

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	goredis "github.com/redis/go-redis/v9"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "redis"

	storageList    = "list"
	storageHashmap = "hashmap"
	storageStream  = "stream"

	defaultKey = "falco"
	// streamField is the stream entry field holding the event JSON.
	streamField = "event"
)

type config struct {
	TLS         shared.TLSClientConfig `mapstructure:"tls"`
	Address     string                 `mapstructure:"address"`
	Username    string                 `mapstructure:"username"`
	Password    string                 `mapstructure:"password"`
	StorageType string                 `mapstructure:"storage_type"`
	Key         string                 `mapstructure:"key"`
	Runtime     output.RuntimeConfig   `mapstructure:"runtime"`
	Database    int                    `mapstructure:"database"`
	MaxLen      int64                  `mapstructure:"max_len"`
	TLSEnabled  bool                   `mapstructure:"tls_enabled"`
}

// OutputType describes the Redis output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryStorage,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{
				Name: "address", Type: "string", Required: true, Label: "Address (host:port)",
				Description: "Redis server as `host:port`, without scheme or credentials.",
			},
			{
				Name: "username", Type: "string", Label: "Username (ACL)",
				Description: "ACL user; requires a password. Empty authenticates as the default user when a password is set.",
			},
			{
				Name: "password", Type: "string", Secret: true, Label: "Password",
				Description: "Password sent with `AUTH`, for the ACL user or the default user. Empty sends no `AUTH`.",
			},
			{
				Name: "database", Type: "int", Default: 0, Label: "Database",
				Description: "Database number selected on each connection, `0` or greater.",
			},
			{
				Name: "storage_type", Type: "enum", Values: []string{storageList, storageHashmap, storageStream}, Default: storageList, Label: "Storage Type",
				Description: "How the event JSON is stored under `key`: `list` appends with `RPUSH`, `hashmap` sets the event UUID field with `HSET`, " +
					"`stream` adds an entry with field `event` with `XADD`.",
			},
			{
				Name: "key", Type: "string", Default: defaultKey, Label: "Key",
				Description: "Name of the list, hash or stream that receives the events.",
			},
			{
				Name: "max_len", Type: "int", Default: 0, Label: "Approximate Stream Length Cap (0 = unbounded)",
				Description: "Approximate stream length kept by `XADD MAXLEN ~`, trimming the oldest entries. Only with `storage_type` `stream`.",
			},
			{
				Name: "tls_enabled", Type: "bool", Default: false, Label: "Enable TLS",
				Description: "Connects to Redis over TLS. `tls` settings are refused unless this is set.",
			},
		}, append(shared.TLSClientSchemaFields(), shared.BatchRuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	client *goredis.Client
	opts   *goredis.Options
	cfg    config
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Address == "" {
		errs.Add("address", "is required")
	} else {
		errs.Merge("address", shared.ValidateBrokers([]string{c.Address}))
	}
	if c.Database < 0 {
		errs.Add("database", "must be 0 or greater")
	}
	switch c.StorageType {
	case storageList, storageHashmap, storageStream:
	default:
		errs.Add("storage_type", "must be list/hashmap/stream")
	}
	if c.MaxLen < 0 {
		errs.Add("max_len", "must be 0 or greater")
	}
	if c.MaxLen > 0 && c.StorageType != storageStream {
		errs.Add("max_len", "applies only to storage_type stream")
	}
	if c.Key == "" {
		errs.Add("key", "is required")
	}
	if c.Username != "" && c.Password == "" {
		errs.Add("password", "is required when username is set")
	}
	errs.Merge("tls", c.TLS.Validate())
	if !c.TLSEnabled && c.TLS != (shared.TLSClientConfig{}) {
		errs.Add("tls", "is set but tls_enabled is false")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	cfg := config{StorageType: storageList, Key: defaultKey}
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	opts := &goredis.Options{
		Addr:     cfg.Address,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.Database,
		// The pipeline owns retries; deadlines come from the caller's context.
		MaxRetries:            -1,
		DialerRetries:         1,
		ContextTimeoutEnabled: true,
	}
	if cfg.TLSEnabled {
		tlsCfg, err := shared.BuildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("%s tls: %w", name, err)
		}
		opts.TLSConfig = tlsCfg
	}
	return &driver{cfg: cfg, opts: opts}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

// clientLogger logs the process-wide go-redis log at debug: its failures also reach the output status.
type clientLogger struct{}

// Printf logs only the library's format string: its arguments can carry server replies.
func (clientLogger) Printf(ctx context.Context, format string, _ ...any) {
	slog.DebugContext(ctx, "redis client event", "output", name, "format", format)
}

var setClientLogger sync.Once

// Init creates the client; connections open on first use.
func (d *driver) Init(_ context.Context) error {
	setClientLogger.Do(func() { goredis.SetLogger(clientLogger{}) })
	d.client = goredis.NewClient(d.opts)
	return nil
}

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	payloads := make([][]byte, len(events))
	for i, evt := range events {
		payload, err := json.Marshal(evt)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpMarshal, err)
		}
		payloads[i] = payload
	}
	if len(payloads) == 1 {
		if err := d.store(ctx, d.client, events[0], payloads[0]).Err(); err != nil {
			return newDeliveryError(shared.OpSend, err)
		}
		return nil
	}
	cmds, err := d.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, evt := range events {
			d.store(ctx, pipe, evt, payloads[i])
		}
		return nil
	})
	if err == nil {
		return nil
	}
	// Exec returns only the first failed command; every command's own result decides the batch.
	var failures []*shared.DeliveryError
	for _, cmd := range cmds {
		if cmdErr := cmd.Err(); cmdErr != nil {
			failures = append(failures, newDeliveryError(shared.OpSend, cmdErr))
		}
	}
	if len(failures) == 0 {
		return newDeliveryError(shared.OpSend, err)
	}
	return shared.JoinDeliveryErrors(ctx, name, shared.OpSend, failures, len(failures), len(cmds), "commands")
}

func (d *driver) store(ctx context.Context, c goredis.Cmdable, evt *event.Event, payload []byte) goredis.Cmder {
	switch d.cfg.StorageType {
	case storageHashmap:
		return c.HSet(ctx, d.cfg.Key, evt.UUID, payload)
	case storageStream:
		return c.XAdd(ctx, &goredis.XAddArgs{
			Stream: d.cfg.Key, MaxLen: d.cfg.MaxLen, Approx: d.cfg.MaxLen > 0,
			Values: []any{streamField, payload},
		})
	default:
		return c.RPush(ctx, d.cfg.Key, payload)
	}
}

// HealthCheck sends PING, which also authenticates and selects the database.
func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	err := d.client.Ping(ctx).Err()
	if err == nil {
		return nil
	}
	diagnostic := newDeliveryError(shared.OpHealthcheck, err)
	diagnostic.Misconfigured = isMisconfiguration(err)
	return diagnostic
}

// isMisconfiguration reports errors that no retry can fix.
func isMisconfiguration(err error) bool {
	return goredis.IsAuthError(err) ||
		goredis.IsPermissionError(err) ||
		goredis.HasErrorPrefix(err, "AUTH") ||
		goredis.HasErrorPrefix(err, "DB index is out of range") ||
		shared.IsTLSVerificationError(err)
}

// Close closes the client; nothing is buffered.
func (d *driver) Close() error {
	if d.client == nil {
		return nil
	}
	if err := d.client.Close(); err != nil {
		return newDeliveryError(shared.OpClose, err)
	}
	return nil
}

// replyPrefixes are the error prefixes Redis documents, mapped to whether the same command can never succeed:
// a key of another type or rejected credentials. Every other reply, BUSY or LOADING included, is retried.
// The rest of a reply can echo submitted values.
// https://redis.io/docs/latest/develop/reference/protocol-spec/#simple-errors
var replyPrefixes = map[string]bool{
	"WRONGTYPE": true, "WRONGPASS": true, "NOAUTH": true, "NOPERM": true,
	"ERR": false, "LOADING": false, "READONLY": false, "OOM": false, "BUSY": false, "NOSCRIPT": false, "MOVED": false,
	"ASK": false, "TRYAGAIN": false, "CLUSTERDOWN": false, "CROSSSLOT": false, "MASTERDOWN": false, "EXECABORT": false,
	"NOREPLICAS": false, "MISCONF": false, "NOTBUSY": false, "BUSYGROUP": false, "NOGROUP": false, "UNBLOCKED": false,
	"NOPROTO": false,
}

// newDeliveryError names a server error reply by its documented prefix only.
func newDeliveryError(operation string, err error) *shared.DeliveryError {
	if _, ok := errors.AsType[goredis.Error](err); !ok {
		return shared.NewDeliveryError(name, operation, err)
	}
	code, _, _ := strings.Cut(err.Error(), " ")
	permanent, documented := replyPrefixes[code]
	if !documented {
		code = "server error"
	}
	return &shared.DeliveryError{Cause: err, Output: name, Operation: operation, Code: code, Permanent: permanent}
}

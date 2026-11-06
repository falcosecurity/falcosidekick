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

package awss3

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	sharedaws "github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name             = "awss3"
	defaultPrefix    = "falco"
	defaultCannedACL = string(s3types.ObjectCannedACLBucketOwnerFullControl)

	contentTypeJSON   = "application/json"
	contentTypeNDJSON = "application/x-ndjson"
)

// bucketPattern also accepts the dotted names some S3-compatible stores allow.
var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

var cannedACLs = func() []string {
	acls := s3types.ObjectCannedACL("").Values()
	values := make([]string, 0, len(acls))
	for _, v := range acls {
		values = append(values, string(v))
	}
	return values
}()

type config struct {
	Bucket           string `mapstructure:"bucket"`
	Prefix           string `mapstructure:"prefix"`
	ObjectCannedACL  string `mapstructure:"object_canned_acl"`
	sharedaws.Config `mapstructure:",squash"`
	Runtime          output.RuntimeConfig `mapstructure:"runtime"`
	UsePathStyle     bool                 `mapstructure:"use_path_style"`
}

// OutputType describes the AWS S3 output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "storage",
	Schema: output.Schema{
		Fields: append(append([]output.SchemaField{
			{Name: "bucket", Type: "string", Required: true, Label: "Bucket"},
			{Name: "prefix", Type: "string", Default: defaultPrefix, Label: "Key Prefix"},
			{Name: "object_canned_acl", Type: "enum", Values: cannedACLs, Default: defaultCannedACL, Label: "Object Canned ACL"},
			{Name: "use_path_style", Type: "bool", Default: false, Label: "Path-style addressing (for S3-compatible endpoints)"},
		}, sharedaws.SchemaFields()...), shared.RuntimeConfigSchemaFields()...),
	},
}

type driver struct {
	client *s3.Client
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.Config.Validate())
	if c.Bucket == "" {
		errs.Add("bucket", "is required")
	} else if !bucketPattern.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") {
		errs.Add("bucket", fmt.Sprintf("invalid bucket name %q", c.Bucket))
	}
	c.Prefix = strings.Trim(c.Prefix, "/")
	if c.Prefix == "" {
		c.Prefix = defaultPrefix
	}
	if c.ObjectCannedACL == "" {
		c.ObjectCannedACL = defaultCannedACL
	} else if !slices.Contains(cannedACLs, c.ObjectCannedACL) {
		errs.Add("object_canned_acl", fmt.Sprintf("must be one of %s, got %q", strings.Join(cannedACLs, "/"), c.ObjectCannedACL))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	awsCfg, err := cfg.Load(context.Background(), "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.UsePathStyle = cfg.UsePathStyle })
	return &driver{client: client, cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}
	return d.put(ctx, d.objectKey(evt, ".json"), body, contentTypeJSON)
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}
	var body []byte
	for _, evt := range events {
		line, err := json.Marshal(evt)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpMarshal, err)
		}
		body = append(append(body, line...), '\n')
	}
	return d.put(ctx, d.objectKey(events[0], ".ndjson"), body, contentTypeNDJSON)
}

func (d *driver) put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := d.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      sdkaws.String(d.cfg.Bucket),
		Key:         sdkaws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: sdkaws.String(contentType),
		ACL:         s3types.ObjectCannedACL(d.cfg.ObjectCannedACL),
		// Object Lock buckets reject PutObject requests carrying no integrity value.
		ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc32,
	})
	return d.cfg.WrapError(name, "PutObject", err)
}

// objectKey includes the event UUID so a retried delivery overwrites the same object.
func (d *driver) objectKey(evt *event.Event, ext string) string {
	t := evt.Time
	if t.IsZero() {
		t = time.Now()
	}
	t = t.UTC()
	id := evt.UUID
	if id == "" {
		id = uuid.NewString()
	}
	return fmt.Sprintf("%s/%s/%s_%s%s", d.cfg.Prefix, t.Format(time.DateOnly), t.Format(time.RFC3339Nano), id, ext)
}

// HealthCheck sends HeadBucket, which needs s3:ListBucket on the bucket.
func (d *driver) HealthCheck(ctx context.Context) error {
	_, err := d.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: sdkaws.String(d.cfg.Bucket)})
	return d.cfg.WrapProbeError(name, "HeadBucket", err)
}

func (d *driver) Close() error { return nil }

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

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envAWSEndpoint is the LocalStack endpoint for S3, SQS and SNS; AWS tests skip without it.
const envAWSEndpoint = "FALCOSIDEKICK_E2E_AWS_ENDPOINT"

const (
	awsRegion      = "us-east-1"
	awsAccessKeyID = "test"
)

// awsTarget carries a per-test secret key that must never appear in logs or API answers.
type awsTarget struct {
	cfg      aws.Config
	endpoint string
	secret   string
}

func localstack(t *testing.T) *awsTarget {
	t.Helper()
	endpoint := strings.TrimSuffix(requireEnv(t, envAWSEndpoint), "/")
	secret := "fsk-e2e-aws-secret-" + newMarker(t)
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(awsRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsAccessKeyID, secret, "")),
	)
	require.NoError(t, err)
	cfg.BaseEndpoint = aws.String(endpoint)
	return &awsTarget{cfg: cfg, endpoint: endpoint, secret: secret}
}

func (a *awsTarget) output(name, extra string) string {
	out := fmt.Sprintf("%s:\n  region: %s\n  endpoint: %q\n  access_key_id: %s\n  secret_access_key: %q\n",
		name, awsRegion, a.endpoint, awsAccessKeyID, a.secret)
	for line := range strings.SplitSeq(strings.TrimRight(extra, "\n"), "\n") {
		if line != "" {
			out += "  " + line + "\n"
		}
	}
	return out
}

// requireSecretAbsent checks the process logs and the API answers.
func (a *awsTarget) requireSecretAbsent(t *testing.T, sk *sidekick, name string) {
	t.Helper()
	assert.NotContains(t, sk.logs.String(), a.secret)
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/" + name, "/api/v1/pipeline/status/" + name} {
		resp, err := httpDo(http.MethodGet, sk.url+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), a.secret, path)
	}
}

func awsContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	t.Cleanup(cancel)
	return ctx
}

func (a *awsTarget) s3Client() *s3.Client {
	return s3.NewFromConfig(a.cfg, func(o *s3.Options) { o.UsePathStyle = true })
}

func (a *awsTarget) createBucket(t *testing.T, marker string) string {
	t.Helper()
	client := a.s3Client()
	bucket := "fsk-e2e-" + marker
	_, err := client.CreateBucket(awsContext(t), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		list, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if err == nil {
			for _, obj := range list.Contents {
				_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: obj.Key})
			}
		}
		_, _ = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	return bucket
}

func (a *awsTarget) waitObjects(t *testing.T, bucket string, want int) map[string]string {
	t.Helper()
	client := a.s3Client()
	objects := map[string]string{}
	eventuallyf(t, func() bool {
		list, err := client.ListObjectsV2(awsContext(t), &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		require.NoError(t, err)
		return len(list.Contents) >= want
	}, "%d objects in bucket %s", want, bucket)
	list, err := client.ListObjectsV2(awsContext(t), &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	for _, obj := range list.Contents {
		got, err := client.GetObject(awsContext(t), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: obj.Key})
		require.NoError(t, err)
		body, err := io.ReadAll(got.Body)
		_ = got.Body.Close()
		require.NoError(t, err)
		objects[aws.ToString(obj.Key)] = string(body)
	}
	return objects
}

func assertAWSEvent(t *testing.T, body, marker string) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &got), body)
	assert.Equal(t, "E2E "+marker, got["rule"])
	assert.Equal(t, "warning", got["priority"])
	assert.NotEmpty(t, got["uuid"])
	assert.Equal(t, marker, got["output_fields"].(map[string]any)["e2e.marker"])
}

var s3KeyPattern = regexp.MustCompile(`^falco/\d{4}-\d{2}-\d{2}/\d{4}-\d{2}-\d{2}T[0-9:.]+Z_[0-9a-f-]{36}\.(json|ndjson)$`)

func TestAWSS3DeliversEvent(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	bucket := target.createBucket(t, marker)
	sk := startSidekick(t, target.output("awss3", "bucket: "+bucket+"\nuse_path_style: true\n"))

	sk.postEvent(t, marker)
	objects := target.waitObjects(t, bucket, 1)
	require.Len(t, objects, 1)
	for key, body := range objects {
		assert.Regexp(t, s3KeyPattern, key)
		assert.True(t, strings.HasSuffix(key, ".json"), key)
		assertAWSEvent(t, body, marker)
	}
	st := sk.waitStatus(t, "awss3", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Equal(t, "ok", st.Status)
	target.requireSecretAbsent(t, sk, "awss3")
}

func TestAWSS3DeliversBatchAsNDJSON(t *testing.T) {
	target := localstack(t)
	marker := newMarker(t)
	bucket := target.createBucket(t, marker)
	sk := startSidekick(t, target.output("awss3", "bucket: "+bucket+"\nuse_path_style: true\n"+
		"runtime:\n  batching:\n    enabled: true\n    batch_size: 3\n    flush_interval: 10s\n"))

	markers := []string{marker + "a", marker + "b", marker + "c"}
	for _, m := range markers {
		sk.postEvent(t, m)
	}
	objects := target.waitObjects(t, bucket, 1)
	require.Len(t, objects, 1)
	for key, body := range objects {
		assert.Regexp(t, s3KeyPattern, key)
		assert.True(t, strings.HasSuffix(key, ".ndjson"), key)
		lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
		require.Len(t, lines, len(markers))
		for i, m := range markers {
			assertAWSEvent(t, lines[i], m)
		}
	}
	st := sk.waitStatus(t, "awss3", func(st outputStatus) bool { return st.SentTotal == 3 })
	assert.Zero(t, st.FailedTotal)
}

func TestAWSS3MissingBucketFailsStartup(t *testing.T) {
	target := localstack(t)
	logs := startSidekickFails(t, target.output("awss3", "bucket: fsk-e2e-absent-"+newMarker(t)+"\nuse_path_style: true\n"))
	assert.Contains(t, logs, "health check: awss3 HeadBucket: HTTP 404 Not Found: NotFound")
	assert.NotContains(t, logs, target.secret)
}

// LocalStack community accepts any credentials, so a rejected key cannot be
// produced here; the unit tests cover the classification.
func TestAWSS3RejectedCredentialsFailStartup(t *testing.T) {
	localstack(t)
	t.Skip("LocalStack community does not validate credentials")
}

func TestAWSS3UnreachableStartsDegraded(t *testing.T) {
	target := localstack(t)
	target.endpoint = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	sk := startSidekick(t, target.output("awss3", "bucket: fsk-e2e-unreachable\nuse_path_style: true\n"))
	st := sk.status(t, "awss3")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
	assert.Contains(t, st.LastWarning, "connection refused")
	target.requireSecretAbsent(t, sk, "awss3")
}

// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// TestUploadS3SendsChecksum covers the integrity value S3 requires on PutObject
// for buckets with Object Lock enabled.
func TestUploadS3SendsChecksum(t *testing.T) {
	var body []byte
	var headerChecksum, trailerChecksum string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		headerChecksum = r.Header.Get("x-amz-checksum-crc32")
		trailerChecksum = r.Header.Get("x-amz-trailer")
		w.Header().Set("ETag", `"5d41402abc4b2a76b9719d911017c592"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	config := &types.Configuration{}
	config.AWS.S3.Bucket = "falcosidekick-test"
	config.AWS.S3.Endpoint = ts.URL

	awscfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("id", "secret", ""),
		HTTPClient:  &http.Client{Transport: &redirectTransport{base: http.DefaultTransport, targetURL: ts.URL}},
	}

	client := &Client{
		OutputType:  "AWS",
		Config:      config,
		AWSConfig:   &awscfg,
		PromStats:   &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "outputs_awss3_test_checksum", Help: "test"}, []string{"destination", "status"})},
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
	}

	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client.UploadS3(falcoPayload)

	require.NotEmpty(t, body, "server handler should have received the payload")
	require.True(t, headerChecksum != "" || trailerChecksum != "",
		"PutObject must carry a CRC32 checksum, either as a header or as an aws-chunked trailer")

	if headerChecksum != "" {
		sum := make([]byte, 4)
		binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(body))
		require.Equal(t, base64.StdEncoding.EncodeToString(sum), headerChecksum)
	}
}

// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"expvar"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// recordingCounter keeps the attribute sets passed to With before each Inc.
type recordingCounter struct {
	mu    *sync.Mutex
	attrs []attribute.KeyValue
	incs  *[][]attribute.KeyValue
}

func newRecordingCounter() recordingCounter {
	return recordingCounter{mu: &sync.Mutex{}, incs: &[][]attribute.KeyValue{}}
}

func (r recordingCounter) With(attrs ...attribute.KeyValue) otlpmetrics.Counter {
	return recordingCounter{mu: r.mu, attrs: append(append([]attribute.KeyValue{}, r.attrs...), attrs...), incs: r.incs}
}

func (r recordingCounter) Inc() {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.incs = append(*r.incs, r.attrs)
}

func newYandexTestClient(t *testing.T, name string, otlp recordingCounter) *Client {
	t.Helper()
	config := &types.Configuration{}
	config.Yandex.Region = "ru-central1"
	config.Yandex.S3.Endpoint = "http://127.0.0.1:1"
	config.Yandex.S3.Bucket = "falco"
	config.Yandex.DataStreams.Endpoint = "http://127.0.0.1:1"
	config.Yandex.DataStreams.StreamName = "/ru-central1/folder/db/falco"

	awsCfg := aws.Config{
		Region:      config.Yandex.Region,
		Credentials: credentials.NewStaticCredentialsProvider("id", "secret", ""),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}

	return &Client{
		OutputType: "Yandex",
		Config:     config,
		AWSConfig:  &awsCfg,
		Stats: &types.Statistics{
			YandexS3:          expvar.NewMap(name + "_s3"),
			YandexDataStreams: expvar.NewMap(name + "_datastreams"),
		},
		PromStats:   &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: "test"}, []string{"destination", "status"})}, //nolint:goconst // label names of the production outputs CounterVec
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: otlp},
	}
}

func TestUploadYandexS3ErrorUpdatesStats(t *testing.T) {
	client := newYandexTestClient(t, "yandex_s3_error_test", newRecordingCounter())

	client.UploadYandexS3(types.FalcoPayload{Output: "test"})

	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.YandexS3, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.YandexS3, Error))
}

func TestUploadYandexDataStreamsErrorUsesItsOwnDestination(t *testing.T) {
	otlp := newRecordingCounter()
	client := newYandexTestClient(t, "yandex_datastreams_error_test", otlp)

	client.UploadYandexDataStreams(types.FalcoPayload{Output: "test"})

	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.YandexDataStreams, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.YandexDataStreams, Error))
	require.Equal(t, [][]attribute.KeyValue{{
		attribute.String("destination", "yandexdatastreams"),
		attribute.String("status", Error),
	}}, *otlp.incs)
}

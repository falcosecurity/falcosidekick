// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
)

// NewYandexClient returns a new output.Client for accessing the Yandex API.
func NewYandexClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	// Load the SDK's configuration from environment and shared config, and
	// create the client with this.
	cfg, err := awsConfig.LoadDefaultConfig(context.Background(),
		awsConfig.WithRegion(config.Yandex.Region),
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.Yandex.AccessKeyID, config.Yandex.SecretAccessKey, "")),
	)
	if err != nil {
		log.Fatalf("failed to load SDK configuration, %v", err)
	}

	utils.Log(utils.InfoLvl, "Yandex", "Session has been configured successfully")

	return &Client{
		OutputType:      "Yandex",
		Config:          config,
		AWSConfig:       &cfg,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// UploadYandexS3 uploads payload to Yandex S3
func (c *Client) UploadYandexS3(falcopayload types.FalcoPayload) {
	f, _ := json.Marshal(falcopayload)
	prefix := ""
	t := time.Now()
	if c.Config.Yandex.S3.Prefix != "" {
		prefix = c.Config.Yandex.S3.Prefix
	}
	key := fmt.Sprintf("%s/%s/%s.json", prefix, t.Format("2006-01-02"), t.Format(time.RFC3339Nano))
	_, err := s3.NewFromConfig(*c.AWSConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(c.Config.Yandex.S3.Endpoint)
		o.Region = c.Config.Yandex.Region
		o.UsePathStyle = true
		o.EndpointResolverV2 = s3.NewDefaultEndpointResolverV2()
	}).PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(c.Config.Yandex.S3.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(f),
	})
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:yandexs3", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "yandexs3", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "yandexs3"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" S3", err.Error())
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+" S3", "Upload payload OK")

	go c.CountMetric("outputs", 1, []string{"output:yandexs3", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "yandexs3", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "yandexs3"),
		attribute.String("status", OK)).Inc()
}

// UploadYandexDataStreams uploads payload to Yandex Data Streams
func (c *Client) UploadYandexDataStreams(falcoPayLoad types.FalcoPayload) {
	svc := kinesis.NewFromConfig(*c.AWSConfig, func(o *kinesis.Options) {
		o.BaseEndpoint = aws.String(c.Config.Yandex.DataStreams.Endpoint)
		o.Region = c.Config.Yandex.Region
		o.EndpointResolverV2 = kinesis.NewDefaultEndpointResolverV2()
	})

	f, _ := json.Marshal(falcoPayLoad)
	input := &kinesis.PutRecordInput{
		Data:         f,
		PartitionKey: aws.String(uuid.NewString()),
		StreamName:   aws.String(c.Config.Yandex.DataStreams.StreamName),
	}

	resp, err := svc.PutRecord(context.Background(), input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:yandexdatastreams", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "yandexdatastreams", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "yandexs3"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" Data Streams", err.Error())
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+"Data Streams", fmt.Sprintf("Put Record OK (%v)", resp.SequenceNumber))
	go c.CountMetric("outputs", 1, []string{"output:yandexdatastreams", "status:ok"})
	c.Stats.YandexDataStreams.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "yandexdatastreams", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "yandexs3"),
		attribute.String("status", OK)).Inc()
}

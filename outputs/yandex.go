// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewYandexClient returns a new output.Client for accessing the Yandex API.
func NewYandexClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	resolverFn := func(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
		switch service {
		case endpoints.S3ServiceID:
			return endpoints.ResolvedEndpoint{
				URL:           config.Yandex.S3.Endpoint,
				SigningRegion: "ru-central1",
			}, nil
		case endpoints.KinesisServiceID:
			return endpoints.ResolvedEndpoint{
				URL:           config.Yandex.DataStreams.Endpoint,
				SigningRegion: "ru-central1",
			}, nil
		}

		return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String(config.Yandex.Region),
		Credentials:      credentials.NewStaticCredentials(config.Yandex.AccessKeyID, config.Yandex.SecretAccessKey, ""),
		EndpointResolver: endpoints.ResolverFunc(resolverFn),
	})
	if err != nil {
		log.Printf("[ERROR] : Yandex - %v\n", "Error while creating Yandex Session")
		return nil, errors.New("error while creating Yandex Session")
	}
	log.Printf("[INFO] : Yandex Session has been configured successfully")

	return &Client{
		OutputType:      "Yandex",
		Config:          config,
		AWSSession:      sess,
		Stats:           stats,
		PromStats:       promStats,
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
	_, err := s3.New(c.AWSSession).PutObject(&s3.PutObjectInput{
		Bucket: aws.String(c.Config.Yandex.S3.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(f),
	})
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:yandexs3", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "yandexs3", "status": Error}).Inc()
		log.Printf("[ERROR] : %v S3 - %v\n", c.OutputType, err.Error())
		return
	}

	log.Printf("[INFO]  : %v S3 - Upload payload OK\n", c.OutputType)

	go c.CountMetric("outputs", 1, []string{"output:yandexs3", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "yandexs3", "status": "ok"}).Inc()
}

// UploadYandexDataStreams uploads payload to Yandex Data Streams
func (c *Client) UploadYandexDataStreams(falcoPayLoad types.FalcoPayload) {
	svc := kinesis.New(c.AWSSession)

	f, _ := json.Marshal(falcoPayLoad)
	input := &kinesis.PutRecordInput{
		Data:         f,
		PartitionKey: aws.String(uuid.NewString()),
		StreamName:   aws.String(c.Config.Yandex.DataStreams.StreamName),
	}

	resp, err := svc.PutRecord(input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:yandexdatastreams", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "yandexdatastreams", "status": Error}).Inc()
		log.Printf("[ERROR] : %v Data Streams - %v\n", c.OutputType, err.Error())
		return
	}

	log.Printf("[INFO] : %v Data Streams - Put Record OK (%v)\n", c.OutputType, resp.SequenceNumber)
	go c.CountMetric("outputs", 1, []string{"output:yandexdatastreams", "status:ok"})
	c.Stats.YandexDataStreams.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "yandexdatastreams", "status": "ok"}).Inc()
}

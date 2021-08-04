package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewAWSClient returns a new output.Client for accessing the AWS API.
func NewYandexS3Client(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	if config.Yandex.AccessKeyID != "" && config.Yandex.SecretAccessKey != "" {
		err1 := os.Setenv("AWS_ACCESS_KEY_ID", config.Yandex.AccessKeyID)
		err2 := os.Setenv("AWS_SECRET_ACCESS_KEY", config.Yandex.SecretAccessKey)
		if err1 != nil || err2 != nil {
			log.Printf("[ERROR] : AWS - Error setting AWS env vars")
			return nil, errors.New("Error setting AWS env vars")
		}
	}
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(config.Yandex.Region),
		Endpoint: aws.String(config.Yandex.Endpoint)})
	if err != nil {
		log.Printf("[ERROR] : AWS - %v\n", "Error while creating AWS Session")
		return nil, errors.New("Error while creating AWS Session")
	} else {
		log.Printf("[INFO] : Yandex S3 session has been configured successfully")
	}

	return &Client{
		OutputType:      "YandexS3",
		Config:          config,
		AWSSession:      sess,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// UploadS3 upload payload to S3
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
		go c.CountMetric("outputs", 1, []string{"output:awss3", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "awss3", "status": Error}).Inc()
		log.Printf("[ERROR] : %v S3 - %v\n", c.OutputType, err.Error())
		return
	}

	log.Printf("[INFO]  : %v S3 - Upload payload OK\n", c.OutputType)

	go c.CountMetric("outputs", 1, []string{"output:awss3", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "awss3", "status": "ok"}).Inc()
}

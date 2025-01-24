// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/outputs/otlpmetrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewAWSClient returns a new output.Client for accessing the AWS API.
func NewAWSClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	var region string
	if config.AWS.Region != "" {
		region = config.AWS.Region
	} else if os.Getenv("AWS_REGION") != "" {
		region = os.Getenv("AWS_REGION")
	} else if os.Getenv("AWS_DEFAULT_REGION") != "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	} else {
		metaSession := session.Must(session.NewSession())
		metaClient := ec2metadata.New(metaSession)

		var err error
		region, err = metaClient.Region()
		if err != nil {
			utils.Log(utils.ErrorLvl, "AWS", fmt.Sprintf("Error while getting region from Metadata AWS Session: %v", err.Error()))
			return nil, errors.New("error getting region from metadata")
		}
	}

	if config.AWS.AccessKeyID != "" && config.AWS.SecretAccessKey != "" && region != "" {
		err1 := os.Setenv("AWS_ACCESS_KEY_ID", config.AWS.AccessKeyID)
		err2 := os.Setenv("AWS_SECRET_ACCESS_KEY", config.AWS.SecretAccessKey)
		err3 := os.Setenv("AWS_DEFAULT_REGION", region)
		if err1 != nil || err2 != nil || err3 != nil {
			utils.Log(utils.ErrorLvl, "AWS", "Error setting AWS env vars")
			return nil, errors.New("error setting AWS env vars")
		}
	}

	awscfg := &aws.Config{Region: aws.String(region)}

	if config.AWS.RoleARN != "" {
		baseSess := session.Must(session.NewSession(awscfg))
		stsSvc := sts.New(baseSess)
		stsArIn := new(sts.AssumeRoleInput)
		stsArIn.RoleArn = aws.String(config.AWS.RoleARN)
		stsArIn.RoleSessionName = aws.String(fmt.Sprintf("session-%v", uuid.New().String()))
		if config.AWS.ExternalID != "" {
			stsArIn.ExternalId = aws.String(config.AWS.ExternalID)
		}
		assumedRole, err := stsSvc.AssumeRole(stsArIn)
		if err != nil {
			utils.Log(utils.ErrorLvl, "AWS", "Error while Assuming Role")
			return nil, errors.New("error while assuming role")
		}
		awscfg.Credentials = credentials.NewStaticCredentials(
			*assumedRole.Credentials.AccessKeyId,
			*assumedRole.Credentials.SecretAccessKey,
			*assumedRole.Credentials.SessionToken,
		)
	}

	sess, err := session.NewSession(awscfg)
	if err != nil {
		utils.Log(utils.ErrorLvl, "AWS", fmt.Sprintf("Error while creating AWS Session: %v", err.Error()))
		return nil, errors.New("error while creating AWS Session")
	}

	if config.AWS.CheckIdentity {
		_, err = sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			utils.Log(utils.ErrorLvl, "AWS", fmt.Sprintf("Error while getting AWS Token: %v", err.Error()))
			return nil, errors.New("error while getting AWS Token")
		}
	}

	var endpointURL *url.URL
	endpointURL, err = url.Parse(config.AWS.SQS.URL)
	if err != nil {
		utils.Log(utils.ErrorLvl, "AWS SQS", err.Error())
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:      "AWS",
		EndpointURL:     endpointURL,
		Config:          config,
		AWSSession:      sess,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// InvokeLambda invokes a lambda function
func (c *Client) InvokeLambda(falcopayload types.FalcoPayload) {
	svc := lambda.New(c.AWSSession)

	f, _ := json.Marshal(falcopayload)

	input := &lambda.InvokeInput{
		FunctionName:   aws.String(c.Config.AWS.Lambda.FunctionName),
		InvocationType: aws.String(c.Config.AWS.Lambda.InvocationType),
		LogType:        aws.String(c.Config.AWS.Lambda.LogType),
		Payload:        f,
	}

	c.Stats.AWSLambda.Add("total", 1)

	resp, err := svc.Invoke(input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awslambda", "status:error"})
		c.Stats.AWSLambda.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awslambda", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awslambda"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" Lambda", err.Error())
		return
	}

	if c.Config.Debug {
		r, _ := base64.StdEncoding.DecodeString(*resp.LogResult)
		utils.Log(utils.DebugLvl, c.OutputType+" Lambda", fmt.Sprintf("result : %v", string(r)))
	}

	utils.Log(utils.InfoLvl, c.OutputType+" Lambda", fmt.Sprintf("Invoke OK (%v)", *resp.StatusCode))
	go c.CountMetric("outputs", 1, []string{"output:awslambda", "status:ok"})
	c.Stats.AWSLambda.Add("ok", 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awslambda", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awslambda"),
		attribute.String("status", OK)).Inc()
}

// SendMessage sends a message to SQS Queue
func (c *Client) SendMessage(falcopayload types.FalcoPayload) {
	svc := sqs.New(c.AWSSession)

	f, _ := json.Marshal(falcopayload)

	input := &sqs.SendMessageInput{
		MessageBody: aws.String(string(f)),
		QueueUrl:    aws.String(c.Config.AWS.SQS.URL),
	}

	c.Stats.AWSSQS.Add("total", 1)

	resp, err := svc.SendMessage(input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awssqs", "status:error"})
		c.Stats.AWSSQS.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awssqs", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awssqs"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" SQS", err.Error())
		return
	}

	if c.Config.Debug {
		utils.Log(utils.DebugLvl, c.OutputType+" SQS", fmt.Sprintf("MD5OfMessageBody : %v", *resp.MD5OfMessageBody))
	}

	utils.Log(utils.InfoLvl, c.OutputType+" SQS", fmt.Sprintf("Send Message OK (%v)", *resp.MessageId))
	go c.CountMetric("outputs", 1, []string{"output:awssqs", "status:ok"})
	c.Stats.AWSSQS.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awssqs", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awssqs"),
		attribute.String("status", OK)).Inc()
}

// UploadS3 upload payload to S3
func (c *Client) UploadS3(falcopayload types.FalcoPayload) {
	f, _ := json.Marshal(falcopayload)

	prefix := ""
	t := time.Now()
	if c.Config.AWS.S3.Prefix != "" {
		prefix = c.Config.AWS.S3.Prefix
	}

	key := fmt.Sprintf("%s/%s/%s.json", prefix, t.Format("2006-01-02"), t.Format(time.RFC3339Nano))
	awsConfig := aws.NewConfig()
	if c.Config.AWS.S3.Endpoint != "" {
		awsConfig = awsConfig.WithEndpoint(c.Config.AWS.S3.Endpoint)
	}
	resp, err := s3.New(c.AWSSession, awsConfig).PutObject(&s3.PutObjectInput{
		Bucket: aws.String(c.Config.AWS.S3.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(f),
		ACL:    aws.String(c.Config.AWS.S3.ObjectCannedACL),
	})
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awss3", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "awss3", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awss3"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" S3", err.Error())
		return
	}

	if resp.SSECustomerAlgorithm != nil {
		utils.Log(utils.InfoLvl, c.OutputType+" S3", fmt.Sprintf("Upload payload OK (%v)", *resp.SSECustomerKeyMD5))
	} else {
		utils.Log(utils.InfoLvl, c.OutputType+" S3", "Upload payload OK")
	}

	go c.CountMetric("outputs", 1, []string{"output:awss3", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "awss3", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awss3"),
		attribute.String("status", OK)).Inc()
}

// PublishTopic sends a message to a SNS Topic
func (c *Client) PublishTopic(falcopayload types.FalcoPayload) {
	svc := sns.New(c.AWSSession)

	var msg *sns.PublishInput

	if c.Config.AWS.SNS.RawJSON {
		f, _ := json.Marshal(falcopayload)
		msg = &sns.PublishInput{
			Message:  aws.String(string(f)),
			TopicArn: aws.String(c.Config.AWS.SNS.TopicArn),
		}
	} else {
		msg = &sns.PublishInput{
			Message: aws.String(falcopayload.Output),
			MessageAttributes: map[string]*sns.MessageAttributeValue{
				"priority": {
					DataType:    aws.String("String"),
					StringValue: aws.String(falcopayload.Priority.String()),
				},
				"rule": {
					DataType:    aws.String("String"),
					StringValue: aws.String(falcopayload.Rule),
				},
				"source": {
					DataType:    aws.String("String"),
					StringValue: aws.String(falcopayload.Source),
				},
			},
			TopicArn: aws.String(c.Config.AWS.SNS.TopicArn),
		}

		if len(falcopayload.Tags) != 0 {
			msg.MessageAttributes["tags"] = &sns.MessageAttributeValue{
				DataType:    aws.String("String"),
				StringValue: aws.String(strings.Join(falcopayload.Tags, ",")),
			}
		}
		if falcopayload.Hostname != "" {
			msg.MessageAttributes[Hostname] = &sns.MessageAttributeValue{
				DataType:    aws.String("String"),
				StringValue: aws.String(falcopayload.Hostname),
			}
		}
		for i, j := range falcopayload.OutputFields {
			m := strings.ReplaceAll(strings.ReplaceAll(i, "]", ""), "[", ".")
			switch j.(type) {
			case string:
				msg.MessageAttributes[m] = &sns.MessageAttributeValue{
					DataType:    aws.String("String"),
					StringValue: aws.String(fmt.Sprintf("%v", j)),
				}
			case json.Number:
				msg.MessageAttributes[m] = &sns.MessageAttributeValue{
					DataType:    aws.String("Number"),
					StringValue: aws.String(fmt.Sprintf("%v", j)),
				}
			default:
				continue
			}
		}
	}

	if c.Config.Debug {
		p, _ := json.Marshal(msg)
		utils.Log(utils.DebugLvl, c.OutputType+" SNS", fmt.Sprintf("Message : %v", string(p)))
	}

	c.Stats.AWSSNS.Add("total", 1)
	resp, err := svc.Publish(msg)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awssns", "status:error"})
		c.Stats.AWSSNS.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awssns", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awssns"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" SNS", err.Error())
		return
	}

	utils.Log(utils.DebugLvl, c.OutputType+" SNS", fmt.Sprintf("Send to topic OK (%v)", *resp.MessageId))
	go c.CountMetric("outputs", 1, []string{"output:awssns", "status:ok"})
	c.Stats.AWSSNS.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awssns", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awssns"),
		attribute.String("status", OK)).Inc()
}

// SendCloudWatchLog sends a message to CloudWatch Log
func (c *Client) SendCloudWatchLog(falcopayload types.FalcoPayload) {
	svc := cloudwatchlogs.New(c.AWSSession)

	f, _ := json.Marshal(falcopayload)

	c.Stats.AWSCloudWatchLogs.Add(Total, 1)

	if c.Config.AWS.CloudWatchLogs.LogStream == "" {
		streamName := "falcosidekick-logstream"
		utils.Log(utils.InfoLvl, c.OutputType+" CloudWatchLogs", fmt.Sprintf("Log Stream not configured creating one called %s", streamName))
		inputLogStream := &cloudwatchlogs.CreateLogStreamInput{
			LogGroupName:  aws.String(c.Config.AWS.CloudWatchLogs.LogGroup),
			LogStreamName: aws.String(streamName),
		}

		_, err := svc.CreateLogStream(inputLogStream)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudwatchlogs.ErrCodeResourceAlreadyExistsException {
				utils.Log(utils.InfoLvl, c.OutputType+" CloudWatchLogs", fmt.Sprintf("Log Stream %s already exist, reusing...", streamName))
			} else {
				go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:error"})
				c.Stats.AWSCloudWatchLogs.Add(Error, 1)
				c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": Error}).Inc()
				c.OTLPMetrics.Outputs.With(attribute.String("destination", "awscloudwatchlogs"),
					attribute.String("status", Error)).Inc()
				utils.Log(utils.ErrorLvl, c.OutputType+" CloudWatchLogs", err.Error())
				return
			}
		}

		c.Config.AWS.CloudWatchLogs.LogStream = streamName
	}

	logevent := &cloudwatchlogs.InputLogEvent{
		Message:   aws.String(string(f)),
		Timestamp: aws.Int64(falcopayload.Time.UnixNano() / int64(time.Millisecond)),
	}

	input := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     []*cloudwatchlogs.InputLogEvent{logevent},
		LogGroupName:  aws.String(c.Config.AWS.CloudWatchLogs.LogGroup),
		LogStreamName: aws.String(c.Config.AWS.CloudWatchLogs.LogStream),
	}

	var err error
	resp, err := c.putLogEvents(svc, input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:error"})
		c.Stats.AWSCloudWatchLogs.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awscloudwatchlogs"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" CloudWatchLogs", err.Error())
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+" CloudWatchLogs", fmt.Sprintf("Send Log OK (%v)", resp.String()))
	go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:ok"})
	c.Stats.AWSCloudWatchLogs.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awscloudwatchlogs"),
		attribute.String("status", OK)).Inc()
}

// PutLogEvents will attempt to execute and handle invalid tokens.
func (c *Client) putLogEvents(svc *cloudwatchlogs.CloudWatchLogs, input *cloudwatchlogs.PutLogEventsInput) (*cloudwatchlogs.PutLogEventsOutput, error) {
	resp, err := svc.PutLogEvents(input)
	if err != nil {
		if exception, ok := err.(*cloudwatchlogs.InvalidSequenceTokenException); ok {
			utils.Log(utils.InfoLvl, c.OutputType+" CloudWatchLogs", fmt.Sprintf("Refreshing token for LogGroup: %s LogStream: %s", *input.LogGroupName, *input.LogStreamName))
			input.SequenceToken = exception.ExpectedSequenceToken

			return c.putLogEvents(svc, input)
		}

		return nil, err
	}

	return resp, nil
}

// PutRecord puts a record in Kinesis
func (c *Client) PutRecord(falcoPayLoad types.FalcoPayload) {
	svc := kinesis.New(c.AWSSession)

	c.Stats.AWSKinesis.Add(Total, 1)

	f, _ := json.Marshal(falcoPayLoad)
	input := &kinesis.PutRecordInput{
		Data:         f,
		PartitionKey: aws.String(uuid.NewString()),
		StreamName:   aws.String(c.Config.AWS.Kinesis.StreamName),
	}

	resp, err := svc.PutRecord(input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awskinesis", "status:error"})
		c.Stats.AWSKinesis.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awskinesis", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "awskinesis"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" Kinesis", err.Error())
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+" Kinesis", fmt.Sprintf("Put Record OK (%v)", resp.SequenceNumber))
	go c.CountMetric("outputs", 1, []string{"output:awskinesis", "status:ok"})
	c.Stats.AWSKinesis.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awskinesis", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "awskinesis"),
		attribute.String("status", OK)).Inc()
}

package outputs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/falcosecurity/falcosidekick/types"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sts"
)

// NewAWSClient returns a new output.Client for accessing the AWS API.
func NewAWSClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	if config.AWS.AccessKeyID != "" && config.AWS.SecretAccessKey != "" && config.AWS.Region != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", config.AWS.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", config.AWS.SecretAccessKey)
		os.Setenv("AWS_DEFAULT_REGION", config.AWS.Region)
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(config.AWS.Region)},
	)
	if err != nil {
		log.Printf("[ERROR] : AWS - %v\n", "Error while creating AWS Session")
		return nil, errors.New("Error while creating AWS Session")
	}

	_, err = sts.New(session.New()).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Printf("[ERROR] : AWS - %v\n", "Error while getting AWS Token")
		return nil, errors.New("Error while getting AWS Token")
	}

	var endpointURL *url.URL
	endpointURL, err = url.Parse(config.AWS.SQS.URL)
	if err != nil {
		log.Printf("[ERROR] : AWS SQS - %v\n", err.Error())
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:      "AWS",
		EndpointURL:     endpointURL,
		Config:          config,
		AWSSession:      sess,
		Stats:           stats,
		PromStats:       promStats,
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
		log.Printf("[ERROR] : %v Lambda - %v\n", c.OutputType, err.Error())
		return
	}

	if c.Config.Debug == true {
		r, _ := base64.StdEncoding.DecodeString(*resp.LogResult)
		log.Printf("[DEBUG] : %v Lambda result : %v\n", c.OutputType, string(r))
	}

	log.Printf("[INFO]  : %v Lambda - Invoke OK (%v)\n", c.OutputType, *resp.StatusCode)
	go c.CountMetric("outputs", 1, []string{"output:awslambda", "status:ok"})
	c.Stats.AWSLambda.Add("ok", 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awslambda", "status": "ok"}).Inc()
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
		log.Printf("[ERROR] : %v SQS - %v\n", c.OutputType, err.Error())
		return
	}

	if c.Config.Debug == true {
		log.Printf("[DEBUG] : %v SQS - MD5OfMessageBody : %v\n", c.OutputType, *resp.MD5OfMessageBody)
	}

	log.Printf("[INFO]  : %v SQS - Send Message OK (%v)\n", c.OutputType, *resp.MessageId)
	go c.CountMetric("outputs", 1, []string{"output:awssqs", "status:ok"})
	c.Stats.AWSSQS.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awssqs", "status": "ok"}).Inc()
}

// PublishTopic sends a message to a SNS Topic
func (c *Client) PublishTopic(falcopayload types.FalcoPayload) {
	svc := sns.New(c.AWSSession)

	var msg *sns.PublishInput

	if c.Config.AWS.SNS.RawJSON == true {
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
			},
			TopicArn: aws.String(c.Config.AWS.SNS.TopicArn),
		}

		for i, j := range falcopayload.OutputFields {
			switch v := j.(type) {
			case string:
				msg.MessageAttributes[i] = &sns.MessageAttributeValue{
					DataType:    aws.String("String"),
					StringValue: aws.String(v),
				}
			default:
				continue
			}
		}
	}

	if c.Config.Debug == true {
		p, _ := json.Marshal(msg)
		log.Printf("[DEBUG] : %v SNS - Message : %v\n", c.OutputType, string(p))
	}

	c.Stats.AWSSNS.Add("total", 1)
	resp, err := svc.Publish(msg)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awssns", "status:error"})
		c.Stats.AWSSNS.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awssns", "status": Error}).Inc()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	log.Printf("[INFO]  : %v SNS - Send to topic OK (%v)\n", c.OutputType, *resp.MessageId)
	go c.CountMetric("outputs", 1, []string{"output:awssns", "status:ok"})
	c.Stats.AWSSNS.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awssns", "status": OK}).Inc()
}

// SendCloudWatchLog sends a message to CloudWatch Log
func (c *Client) SendCloudWatchLog(falcopayload types.FalcoPayload) {
	svc := cloudwatchlogs.New(c.AWSSession)

	f, _ := json.Marshal(falcopayload)

	c.Stats.AWSCloudWatchLogs.Add(Total, 1)

	if c.Config.AWS.CloudWatchLogs.LogStream == "" {
		streamName := "falcosidekick-logstream"
		log.Printf("[INFO]  : %v CloudWatchLogs - Log Stream not configured creating one called %s\n", c.OutputType, streamName)
		inputLogStream := &cloudwatchlogs.CreateLogStreamInput{
			LogGroupName:  aws.String(c.Config.AWS.CloudWatchLogs.LogGroup),
			LogStreamName: aws.String(streamName),
		}

		_, err := svc.CreateLogStream(inputLogStream)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudwatchlogs.ErrCodeResourceAlreadyExistsException {
				log.Printf("[INFO]  : %v CloudWatchLogs - Log Stream %s already exist, reusing...\n", c.OutputType, streamName)
			} else {
				go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:error"})
				c.Stats.AWSCloudWatchLogs.Add(Error, 1)
				c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": Error}).Inc()
				log.Printf("[ERROR] : %v CloudWatchLogs - %v\n", c.OutputType, err.Error())
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
	resp := &cloudwatchlogs.PutLogEventsOutput{}
	resp, err = c.putLogEvents(svc, input)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:error"})
		c.Stats.AWSCloudWatchLogs.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": Error}).Inc()
		log.Printf("[ERROR] : %v CloudWatchLogs - %v\n", c.OutputType, err.Error())
		return
	}

	log.Printf("[INFO]  : %v CloudWatchLogs - Send Log OK (%v)\n", c.OutputType, resp.String())
	go c.CountMetric("outputs", 1, []string{"output:awscloudwatchlogs", "status:ok"})
	c.Stats.AWSCloudWatchLogs.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "awscloudwatchlogs", "status": OK}).Inc()
}

// PutLogEvents will attempt to execute and handle invalid tokens.
func (c *Client) putLogEvents(svc *cloudwatchlogs.CloudWatchLogs, input *cloudwatchlogs.PutLogEventsInput) (*cloudwatchlogs.PutLogEventsOutput, error) {
	resp, err := svc.PutLogEvents(input)
	if err != nil {
		if exception, ok := err.(*cloudwatchlogs.InvalidSequenceTokenException); ok {
			log.Printf("[INFO]  : %v Refreshing token for LogGroup: %s LogStream: %s", c.OutputType, *input.LogGroupName, *input.LogStreamName)
			input.SequenceToken = exception.ExpectedSequenceToken

			return c.putLogEvents(svc, input)
		}

		return nil, err
	}

	return resp, nil
}

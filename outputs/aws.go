package outputs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"

	"github.com/Issif/falcosidekick/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sts"
)

// NewAWSClient returns a new output.Client for accessing the AWS API.
func NewAWSClient(outputType string, config *types.Configuration, stats *types.Statistics) (*Client, error) {

	if config.AWS.AccessKeyID != "" && config.AWS.SecretAccessKey != "" && config.AWS.Region != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", config.AWS.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", config.AWS.SecretAccessKey)
		os.Setenv("AWS_DEFAULT_REGION", config.AWS.Region)
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(config.AWS.Region)},
	)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", outputType, "Error while creating AWS Session")
		return nil, errors.New("Error while creating AWS Session")
	}

	_, err = sts.New(session.New()).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", outputType, "Error while getting AWS Token")
		return nil, errors.New("Error while getting AWS Token")
	}

	var endpointURL *url.URL
	endpointURL, err = url.Parse(config.AWS.SQS.URL)
	if err != nil {
		log.Printf("[ERROR] : %v SQS - %v\n", outputType, err.Error())
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:  outputType,
		EndpointURL: endpointURL,
		Config:      config,
		AWSSession:  sess,
		Stats:       stats,
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
		c.Stats.AWSLambda.Add("error", 1)
		log.Printf("[ERROR] : %v Lambda - %v\n", c.OutputType, err.Error())
		return
	}

	if c.Config.Debug == true {
		r, _ := base64.StdEncoding.DecodeString(*resp.LogResult)
		log.Printf("[DEBUG] : %v Lambda result : %v\n", c.OutputType, string(r))
	}

	log.Printf("[INFO]  : %v Lambda - Invoke OK (%v)\n", c.OutputType, *resp.StatusCode)
	c.Stats.AWSLambda.Add("sent", 1)
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
		c.Stats.AWSSQS.Add("error", 1)
		log.Printf("[ERROR] : %v SQS - %v\n", c.OutputType, err.Error())
		return
	}

	if c.Config.Debug == true {
		log.Printf("[DEBUG] : %v SQS - MD5OfMessageBody : %v\n", c.OutputType, *resp.MD5OfMessageBody)
	}

	log.Printf("[INFO]  : %v SQS - Send Message OK (%v)\n", c.OutputType, *resp.MessageId)
	c.Stats.AWSSQS.Add("sent", 1)
}

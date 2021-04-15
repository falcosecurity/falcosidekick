package outputs

import (
	"log"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
)

type mockCloudWatchLogsClient struct {
	cloudwatchlogsiface.CloudWatchLogsAPI
}

func (m *mockCloudWatchLogsClient) CreateLogStream(input *cloudwatchlogs.CreateLogStreamInput) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	// Make response
	output := &cloudwatchlogs.CreateLogStreamOutput{}
	// Returned canned response
	return output, nil
}

func (m *mockCloudWatchLogsClient) PutLogEvents(input *cloudwatchlogs.PutLogEventsInput) (*cloudwatchlogs.PutLogEventsOutput, error) {
	// Make Fake response
	output := &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: aws.String("49615979181672665396714842137235223898179389223829386111"),
	}
	// Returned canned response
	return output, nil
}

func CallCreateLogStream(svc cloudwatchlogsiface.CloudWatchLogsAPI) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	inputLogStream := &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String("test-loggroup"),
		LogStreamName: aws.String("test-logstream"),
	}
	result, err := svc.CreateLogStream(inputLogStream)
	if err != nil {
		log.Printf("[Error]  : Creating Mock Log Stream")
	}
	return result, err
}

func CallPutLogEvents(svc cloudwatchlogsiface.CloudWatchLogsAPI) (*cloudwatchlogs.PutLogEventsOutput, error) {
	input := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     []*cloudwatchlogs.InputLogEvent{},
		LogGroupName:  aws.String("test-loggroup"),
		LogStreamName: aws.String("test-logstream"),
	}
	result, err := svc.PutLogEvents(input)
	if err != nil {
		log.Printf("[Error]  : Creating Mock Log Stream")
	}
	return result, err
}

func TestCreateLogStream(t *testing.T) {
	// Make response
	svc := &mockCloudWatchLogsClient{}
	_, err := CallCreateLogStream(svc)
	if err != nil {
		t.Errorf("Error calling CreateLogStream %d", err)
	}
	res, err2 := CallPutLogEvents(svc)
	if err2 != nil {
		t.Errorf("Error calling CallPutLogEvents %d", err)
	}
	if *res.NextSequenceToken != "49615979181672665396714842137235223898179389223829386111" {
		t.Errorf("Wrong sequence token returned. Should be 49615979181672665396714842137235223898179389223829386111, was %s", res)
	}
}

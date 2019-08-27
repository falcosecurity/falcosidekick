package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"

	"github.com/Issif/falcosidekick/types"
	"github.com/aws/aws-sdk-go/aws/session"
)

// ErrHeaderMissing = 400
var ErrHeaderMissing = errors.New("Header missing")

// ErrClientAuthenticationError = 401
var ErrClientAuthenticationError = errors.New("Authentication Error")

// ErrForbidden = 403
var ErrForbidden = errors.New("Acces Denied")

// ErrNotFound = 404
var ErrNotFound = errors.New("Resource not found")

// ErrUnprocessableEntityError = 422
var ErrUnprocessableEntityError = errors.New("Bad Request")

// ErrTooManyRequest = 429
var ErrTooManyRequest = errors.New("Exceeding post rate limit")

// ErrClientCreation is returned if client can't be created
var ErrClientCreation = errors.New("Client creation Error")

// Client communicates with the different API.
type Client struct {
	OutputType  string
	EndpointURL *url.URL
	Config      *types.Configuration
	Stats       *types.Statistics
	AWSSession  *session.Session
}

// NewClient returns a new output.Client for accessing the different API.
func NewClient(outputType string, defaultEndpointURL string, config *types.Configuration, stats *types.Statistics) (*Client, error) {
	reg := regexp.MustCompile(`http(s?)://.*`)
	if !reg.MatchString(defaultEndpointURL) {
		log.Printf("[ERROR] : %v - %v\n", outputType, "Bad URL")
		return nil, ErrClientCreation
	}
	if _, err := url.ParseRequestURI(defaultEndpointURL); err != nil {
		log.Printf("[ERROR] : %v - %v\n", outputType, err.Error())
		return nil, ErrClientCreation
	}
	endpointURL, err := url.Parse(defaultEndpointURL)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", outputType, err.Error())
		return nil, ErrClientCreation
	}
	return &Client{OutputType: outputType, EndpointURL: endpointURL, Config: config, Stats: stats}, nil
}

// Post sends event (payload) to Output.
func (c *Client) Post(payload interface{}) error {
	// defer + recover to catch panic if output doesn't respond
	defer func() {
		if err := recover(); err != nil {
		}
	}()

	body := new(bytes.Buffer)
	switch payload.(type) {
	case influxdbPayload:
		fmt.Fprintf(body, "%v", payload)
	default:
		json.NewEncoder(body).Encode(payload)
	}

	if c.Config.Debug == true {
		log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, body)
	}

	contentType := "application/json; charset=utf-8"
	if c.OutputType == "Loki" {
		contentType = "application/json"
	}
	resp, err := http.Post(c.EndpointURL.String(), contentType, body)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: //200, 201, 202, 204
		log.Printf("[INFO]  : %v - Post OK (%v)\n", c.OutputType, resp.StatusCode)
		return nil
	case http.StatusBadRequest: //400
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrHeaderMissing, resp.StatusCode)
		return ErrHeaderMissing
	case http.StatusUnauthorized: //401
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrClientAuthenticationError, resp.StatusCode)
		return ErrClientAuthenticationError
	case http.StatusForbidden: //403
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrForbidden, resp.StatusCode)
		return ErrForbidden
	case http.StatusNotFound: //404
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrNotFound, resp.StatusCode)
		return ErrNotFound
	case http.StatusUnprocessableEntity: //422
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrUnprocessableEntityError, resp.StatusCode)
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: //429
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrTooManyRequest, resp.StatusCode)
		return ErrTooManyRequest
	default:
		log.Printf("[ERROR] : %v - Unexpected Response  (%v)\n", c.OutputType, resp.StatusCode)
		return errors.New(resp.Status)
	}
}

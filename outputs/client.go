package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
)

// Different Error Types
var ErrHeaderMissing = errors.New("Header missing")
var ErrNotFound = errors.New("Resource not found")
var ErrClientAuthenticationError = errors.New("Authentication Error")
var ErrForbidden = errors.New("Authentication Error")
var ErrUnprocessableEntityError = errors.New("Bad Request")
var ErrTooManyRequest = errors.New("Exceeding post rate limit")
var ErrClientCreation = errors.New("Client creation Error")

// Client communicates with the different API.
type Client struct {
	OutputType  string
	EndpointURL *url.URL
}

// NewClient returns a new output.Client for accessing the different API.
func NewClient(outpuType string, defaultEndpointURL string) (*Client, error) {
	c := &Client{OutputType: outpuType}
	endpointURL, err := url.Parse(defaultEndpointURL)
	if err != nil {
		return nil, ErrClientCreation
	}
	c.EndpointURL = endpointURL
	return c, nil
}

// Post sends event (payload) to Output.
func (c *Client) Post(payload interface{}) {
	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(payload)

	if os.Getenv("DEBUG") == "true" {
		log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, body)
	}

	resp, err := http.Post(c.EndpointURL.String(), "application/json; charset=utf-8", body)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: //200, 201, 202, 204
		log.Printf("[INFO] : %v - Post OK (%v)\n", c.OutputType, resp.StatusCode)
	case http.StatusBadRequest: //400
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrHeaderMissing)
	case http.StatusUnauthorized: //401
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrClientAuthenticationError)
	case http.StatusForbidden: //403
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrForbidden)
	case http.StatusNotFound: //404
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrNotFound)
	case http.StatusUnprocessableEntity: //422
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrUnprocessableEntityError)
	case http.StatusTooManyRequests: //429
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrTooManyRequest)
	default:
		log.Printf("[ERROR] : %v - Unknown Response: %v\n", c.OutputType, ErrHeaderMissing)
	}
}

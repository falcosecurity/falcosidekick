package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
}

// NewClient returns a new output.Client for accessing the different API.
func NewClient(outputType string, defaultEndpointURL string) (*Client, error) {
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
	return &Client{OutputType: outputType, EndpointURL: endpointURL}, nil
}

// Post sends event (payload) to Output.
func (c *Client) Post(payload interface{}) error {
	// defer + recover to catch panic if output doesn't respond
	defer func() {
		if err := recover(); err != nil {
		}
	}()

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
		log.Printf("[INFO]  : %v - Post OK (%v)\n", c.OutputType, resp.StatusCode)
		return nil
	case http.StatusBadRequest: //400
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrHeaderMissing)
		return ErrHeaderMissing
	case http.StatusUnauthorized: //401
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrClientAuthenticationError)
		return ErrClientAuthenticationError
	case http.StatusForbidden: //403
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrForbidden)
		return ErrForbidden
	case http.StatusNotFound: //404
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrNotFound)
		return ErrNotFound
	case http.StatusUnprocessableEntity: //422
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrUnprocessableEntityError)
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: //429
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, ErrTooManyRequest)
		return ErrTooManyRequest
	default:
		log.Printf("[ERROR] : %v - Unexpected Response\n", c.OutputType)
		return errors.New(resp.Status)
	}
}

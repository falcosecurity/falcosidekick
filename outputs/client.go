// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
	crdClient "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	amqp "github.com/rabbitmq/amqp091-go"
	wavefront "github.com/wavefronthq/wavefront-sdk-go/senders"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws/session"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/segmentio/kafka-go"
	"k8s.io/client-go/kubernetes"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	timescaledb "github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"

	"github.com/falcosecurity/falcosidekick/types"
)

// ErrHeaderMissing = 400
var ErrHeaderMissing = errors.New("header missing")

// ErrClientAuthenticationError = 401
var ErrClientAuthenticationError = errors.New("authentication error")

// ErrForbidden = 403
var ErrForbidden = errors.New("access denied")

// ErrNotFound = 404
var ErrNotFound = errors.New("resource not found")

// ErrUnprocessableEntityError = 422
var ErrUnprocessableEntityError = errors.New("bad request")

// ErrTooManyRequest = 429
var ErrTooManyRequest = errors.New("exceeding post rate limit")

// ErrInternalServer = 500
var ErrInternalServer = errors.New("internal server error")

// ErrBadGateway = 502
var ErrBadGateway = errors.New("bad gateway")

// ErrClientCreation is returned if client can't be created
var ErrClientCreation = errors.New("client creation error")

var ErrSASLAuthCreation = errors.New("sasl auth: wrong mechanism")

// EnabledOutputs list all enabled outputs
var EnabledOutputs []string

// DefaultContentType is the default Content-Type header to send along with the Client's POST Request
const DefaultContentType = "application/json; charset=utf-8"

// Some common header values that may be needed in other files
const ContentTypeHeaderKey = "Content-Type"
const UserAgentHeaderKey = "User-Agent"
const AuthorizationHeaderKey = "Authorization"
const UserAgentHeaderValue = "Falcosidekick"
const Bearer = "Bearer"

// files names are static fo the shake of helm and single docker compatibility
const MutualTLSClientCertFilename = "/client.crt"
const MutualTLSClientKeyFilename = "/client.key"
const MutualTLSCacertFilename = "/ca.crt"

// HTTP Methods
const HttpPost = "POST"
const HttpPut = "PUT"

// Client communicates with the different API.
type Client struct {
	OutputType              string
	EndpointURL             *url.URL
	ContentType             string
	ShutDownFunc            func()
	Config                  *types.Configuration
	Stats                   *types.Statistics
	PromStats               *types.PromStatistics
	AWSSession              *session.Session
	StatsdClient            *statsd.Client
	DogstatsdClient         *statsd.Client
	GCPTopicClient          *pubsub.Topic
	GCPCloudFunctionsClient *gcpfunctions.CloudFunctionsClient

	GCSStorageClient  *storage.Client
	KafkaProducer     *kafka.Writer
	CloudEventsClient cloudevents.Client
	KubernetesClient  kubernetes.Interface
	RabbitmqClient    *amqp.Channel
	WavefrontSender   *wavefront.Sender
	Crdclient         *crdClient.Clientset
	MQTTClient        mqtt.Client
	TimescaleDBClient *timescaledb.Pool
	RedisClient       *redis.Client

	// cached http.Client
	httpcli *http.Client
	// lock for http client creation
	mx  sync.Mutex
	cfg types.CommonConfig

	initOnce sync.Once
	sem      *semaphore.Weighted
}

// InitClient returns a new output.Client for accessing the different API.
func NewClient(outputType string, defaultEndpointURL string, cfg types.CommonConfig, params types.InitClientArgs) (*Client, error) {
	reg := regexp.MustCompile(`(http|nats)(s?)://.*`)
	if !reg.MatchString(defaultEndpointURL) {
		log.Printf("[ERROR] : %v - %v\n", outputType, "Bad Endpoint")
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
	return &Client{
		cfg:             cfg,
		OutputType:      outputType,
		EndpointURL:     endpointURL,
		ContentType:     DefaultContentType,
		Config:          params.Config,
		Stats:           params.Stats,
		PromStats:       params.PromStats,
		StatsdClient:    params.StatsdClient,
		DogstatsdClient: params.DogstatsdClient,
	}, nil
}

type RequestOptionFunc func(req *http.Request)

// Get get a payload from Output with GET http method.
func (c *Client) Get(opts ...RequestOptionFunc) error {
	return c.sendRequest("GET", nil, opts...)
}

// Post sends event (payload) to Output with POST http method.
func (c *Client) Post(payload interface{}, opts ...RequestOptionFunc) error {
	return c.sendRequest("POST", payload, opts...)
}

// Put sends event (payload) to Output with PUT http method.
func (c *Client) Put(payload interface{}, opts ...RequestOptionFunc) error {
	return c.sendRequest("PUT", payload, opts...)
}

// Get the response body as inlined string
func getInlinedBodyAsString(resp *http.Response) string {
	body, _ := io.ReadAll(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/json" {
		var compactedBody bytes.Buffer
		err := json.Compact(&compactedBody, body)
		if err == nil {
			return compactedBody.String()
		}
	}

	return string(body)
}

// Post sends event (payload) to Output.
func (c *Client) sendRequest(method string, payload interface{}, opts ...RequestOptionFunc) error {
	// Initialize the semaphore once here
	// because currently there are multiple code paths
	// where the client is created directly without using NewClient constructor
	c.initOnce.Do(func() {
		if c.cfg.MaxConcurrentRequests == 0 {
			c.sem = semaphore.NewWeighted(math.MaxInt64)
		} else {
			c.sem = semaphore.NewWeighted(int64(c.cfg.MaxConcurrentRequests))
		}
	})

	// defer + recover to catch panic if output doesn't respond
	defer func(c *Client) {
		if err := recover(); err != nil {
			go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:connectionrefused"})
			log.Printf("[ERROR] : %v - %s", c.OutputType, err)
		}
	}(c)

	body := new(bytes.Buffer)
	switch payload.(type) {
	case influxdbPayload:
		fmt.Fprintf(body, "%v", payload)
		if c.Config.Debug {
			log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, body)
		}
	case spyderbatPayload:
		zipper := gzip.NewWriter(body)
		if err := json.NewEncoder(zipper).Encode(payload); err != nil {
			log.Printf("[ERROR] : %v - %s", c.OutputType, err)
		}
		zipper.Close()
		if c.Config.Debug {
			debugBody := new(bytes.Buffer)
			if err := json.NewEncoder(debugBody).Encode(payload); err == nil {
				log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, debugBody)
			}
		}
	default:
		if err := json.NewEncoder(body).Encode(payload); err != nil {
			log.Printf("[ERROR] : %v - %s", c.OutputType, err)
		}
		if c.Config.Debug {
			log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, body)
		}
	}

	client := c.httpClient()

	var req *http.Request
	var err error
	if method == "GET" {
		req, err = http.NewRequest(method, c.EndpointURL.String(), nil)
	} else {
		req, err = http.NewRequest(method, c.EndpointURL.String(), body)
	}
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return err
	}

	req.Header.Add(ContentTypeHeaderKey, c.ContentType)
	req.Header.Add(UserAgentHeaderKey, UserAgentHeaderValue)

	// Call request options functions
	// Allows the clients to adjust request as needed
	for _, opt := range opts {
		opt(req)
	}

	// Using the background context for now
	// TODO: Eventually pass the proper context to sendRequest, and pass it to NewRequest call as well
	// in order to make the requests cancellable
	ctx := context.Background()
	err = c.sem.Acquire(ctx, 1)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return err
	}
	defer c.sem.Release(1)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:connectionrefused"})
		return err
	}
	defer resp.Body.Close()

	// Clear out headers - they will be set for the next request.
	go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:" + strings.ToLower(http.StatusText(resp.StatusCode))})

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: //200, 201, 202, 204
		log.Printf("[INFO]  : %v - %v OK (%v)\n", c.OutputType, method, resp.StatusCode)
		if ot := c.OutputType; ot == Kubeless || ot == Openfaas || ot == Fission {
			log.Printf("[INFO]  : %v - Function Response : %s\n", ot, getInlinedBodyAsString(resp))
		}
		return nil
	case http.StatusBadRequest: //400
		msg := getInlinedBodyAsString(resp)
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrHeaderMissing, resp.StatusCode, msg)
		if msg != "" {
			return fmt.Errorf(msg)
		}
		return ErrHeaderMissing
	case http.StatusUnauthorized: //401
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrClientAuthenticationError, resp.StatusCode, getInlinedBodyAsString(resp))
		return ErrClientAuthenticationError
	case http.StatusForbidden: //403
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrForbidden, resp.StatusCode, getInlinedBodyAsString(resp))
		return ErrForbidden
	case http.StatusNotFound: //404
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrNotFound, resp.StatusCode, getInlinedBodyAsString(resp))
		return ErrNotFound
	case http.StatusUnprocessableEntity: //422
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrUnprocessableEntityError, resp.StatusCode, getInlinedBodyAsString(resp))
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: //429
		log.Printf("[ERROR] : %v - %v (%v): %s\n", c.OutputType, ErrTooManyRequest, resp.StatusCode, getInlinedBodyAsString(resp))
		return ErrTooManyRequest
	case http.StatusInternalServerError: //500
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrTooManyRequest, resp.StatusCode)
		return ErrInternalServer
	case http.StatusBadGateway: //502
		log.Printf("[ERROR] : %v - %v (%v)\n", c.OutputType, ErrTooManyRequest, resp.StatusCode)
		return ErrBadGateway
	default:
		log.Printf("[ERROR] : %v - unexpected Response  (%v)\n", c.OutputType, resp.StatusCode)
		return errors.New(resp.Status)
	}
}

// httpClient returns http client.
// It returns the cached client if it was successfully configured before, for compatibility.
// It returns misconfigured client as before if some of the configuration steps failed.
// It was only logging the failures in it's original implementation, so keeping it the same.
func (c *Client) httpClient() *http.Client {
	c.mx.Lock()
	defer c.mx.Unlock()
	if c.httpcli != nil {
		return c.httpcli
	}

	customTransport, err := c.configureTransport()
	client := &http.Client{
		Transport: customTransport,
	}
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
	} else {
		c.httpcli = client // cache the client instance for future http calls
	}

	return client
}

// configureTransport configure http transport
// This preserves the previous behavior where it only logged errors, but returned misconfigured transport in case of errors
func (c *Client) configureTransport() (*http.Transport, error) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	if customTransport.TLSClientConfig == nil {
		customTransport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	if customTransport.TLSClientConfig.RootCAs == nil {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		customTransport.TLSClientConfig.RootCAs = pool
	}

	if c.Config.TLSClient.CaCertFile != "" {
		caCert, err := os.ReadFile(c.Config.TLSClient.CaCertFile)
		if err != nil {
			return customTransport, err
		}
		customTransport.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)
	}

	if c.cfg.MutualTLS {
		// Load client cert
		var MutualTLSClientCertPath, MutualTLSClientKeyPath, MutualTLSClientCaCertPath string
		if c.Config.MutualTLSClient.CertFile != "" {
			MutualTLSClientCertPath = c.Config.MutualTLSClient.CertFile
		} else {
			MutualTLSClientCertPath = c.Config.MutualTLSFilesPath + MutualTLSClientCertFilename
		}
		if c.Config.MutualTLSClient.KeyFile != "" {
			MutualTLSClientKeyPath = c.Config.MutualTLSClient.KeyFile
		} else {
			MutualTLSClientKeyPath = c.Config.MutualTLSFilesPath + MutualTLSClientKeyFilename
		}
		if c.Config.MutualTLSClient.CaCertFile != "" {
			MutualTLSClientCaCertPath = c.Config.MutualTLSClient.CaCertFile
		} else {
			MutualTLSClientCaCertPath = c.Config.MutualTLSFilesPath + MutualTLSCacertFilename
		}
		cert, err := tls.LoadX509KeyPair(MutualTLSClientCertPath, MutualTLSClientKeyPath)
		if err != nil {
			return customTransport, err
		}

		// Load CA cert
		caCert, err := os.ReadFile(MutualTLSClientCaCertPath)
		if err != nil {
			return customTransport, err
		}
		customTransport.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)
		customTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	} else {
		// With MutualTLS enabled, the check cert flag is ignored
		if !c.cfg.CheckCert {
			customTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 This is only set as a result of explicit configuration
			}
		}
	}
	return customTransport, nil
}

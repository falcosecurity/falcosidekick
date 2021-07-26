package outputs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	crdClient "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/generated/v1alpha2/clientset/versioned"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	"github.com/streadway/amqp"
	wavefront "github.com/wavefronthq/wavefront-sdk-go/senders"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws/session"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/segmentio/kafka-go"
	"k8s.io/client-go/kubernetes"

	"github.com/falcosecurity/falcosidekick/types"
)

// ErrHeaderMissing = 400
var ErrHeaderMissing = errors.New("Header missing")

// ErrClientAuthenticationError = 401
var ErrClientAuthenticationError = errors.New("Authentication Error")

// ErrForbidden = 403
var ErrForbidden = errors.New("Access Denied")

// ErrNotFound = 404
var ErrNotFound = errors.New("Resource not found")

// ErrUnprocessableEntityError = 422
var ErrUnprocessableEntityError = errors.New("Bad Request")

// ErrTooManyRequest = 429
var ErrTooManyRequest = errors.New("Exceeding post rate limit")

// ErrClientCreation is returned if client can't be created
var ErrClientCreation = errors.New("Client creation Error")

// EnabledOutputs list all enabled outputs
var EnabledOutputs []string

// DefaultContentType is the default Content-Type header to send along with the Client's POST Request
const DefaultContentType = "application/json; charset=utf-8"

// Some common header values that may be needed in other files
const ContentTypeHeaderKey = "Content-Type"
const UserAgentHeaderKey = "User-Agent"
const AuthorizationHeaderKey = "Authorization"
const UserAgentHeaderValue = "Falcosidekick"

// files names are static fo the shake of helm and single docker compatibility
const MutualTLSClientCertFilename = "/client.crt"
const MutualTLSClientKeyFilename = "/client.key"
const MutualTLSCacertFilename = "/ca.crt"

// Headers to add to the client before sending the request
type Header struct {
	Key   string
	Value string
}

// Client communicates with the different API.
type Client struct {
	OutputType              string
	EndpointURL             *url.URL
	MutualTLSEnabled        bool
	CheckCert               bool
	HeaderList              []Header
	ContentType             string
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
}

// NewClient returns a new output.Client for accessing the different API.
func NewClient(outputType string, defaultEndpointURL string, mutualTLSEnabled bool, checkCert bool, config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
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
	return &Client{OutputType: outputType, EndpointURL: endpointURL, MutualTLSEnabled: mutualTLSEnabled, HeaderList: []Header{}, ContentType: DefaultContentType, Config: config, Stats: stats, PromStats: promStats, StatsdClient: statsdClient, DogstatsdClient: dogstatsdClient}, nil
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
		if err := json.NewEncoder(body).Encode(payload); err != nil {
			log.Printf("[ERROR] : %v - %s", c.OutputType, err)
		}
	}

	if c.Config.Debug == true {
		log.Printf("[DEBUG] : %v payload : %v\n", c.OutputType, body)
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	if c.MutualTLSEnabled {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(c.Config.MutualTLSFilesPath+MutualTLSClientCertFilename, c.Config.MutualTLSFilesPath+MutualTLSClientKeyFilename)
		if err != nil {
			log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		}

		// Load CA cert
		caCert, err := ioutil.ReadFile(c.Config.MutualTLSFilesPath + MutualTLSCacertFilename)
		if err != nil {
			log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		customTransport.TLSClientConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		// With MutualTLS enabled, the check cert flag is ignored
		if c.CheckCert == false {
			// #nosec G402 This is only set as a result of explicit configuration
			customTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
	}

	client := &http.Client{
		Transport: customTransport,
	}

	req, err := http.NewRequest("POST", c.EndpointURL.String(), body)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
	}

	req.Header.Add(ContentTypeHeaderKey, c.ContentType)
	req.Header.Add(UserAgentHeaderKey, UserAgentHeaderValue)

	for _, headerObj := range c.HeaderList {
		req.Header.Add(headerObj.Key, headerObj.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:connectionrefused"})
		return err
	}
	defer resp.Body.Close()

	// Clear out headers - they will be set for the next request.
	c.HeaderList = []Header{}

	go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:" + strings.ToLower(http.StatusText(resp.StatusCode))})

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: //200, 201, 202, 204
		log.Printf("[INFO]  : %v - Post OK (%v)\n", c.OutputType, resp.StatusCode)
		body, _ := ioutil.ReadAll(resp.Body)
		if c.OutputType == Kubeless {
			log.Printf("[INFO]  : Kubeless - Function Response : %v\n", string(body))
		} else if c.OutputType == Openfaas {
			log.Printf("[INFO]  : %v - Function Response : %v\n", Openfaas,
				string(body))
		} else if c.OutputType == Fission {
			log.Printf("[INFO]  : %v - Function Response : %v\n", Fission, string(body))
		}
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

// BasicAuth adds an HTTP Basic Authentication compliant header to the Client.
func (c *Client) BasicAuth(username, password string) {
	// Check out RFC7617 for the specifics on this code.
	// https://datatracker.ietf.org/doc/html/rfc7617
	// This might break I18n, but we can cross that bridge when we come to it.
	userPass := username + ":" + password
	b64UserPass := base64.StdEncoding.EncodeToString([]byte(userPass))
	c.AddHeader(AuthorizationHeaderKey, "Basic "+b64UserPass)
}

// AddHeader adds an HTTP Header to the Client.
func (c *Client) AddHeader(key, value string) {
	c.HeaderList = append(c.HeaderList, Header{Key: key, Value: value})
}

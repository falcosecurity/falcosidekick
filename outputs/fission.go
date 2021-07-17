package outputs

import (
	"context"
	"encoding/json"
	"log"
	"strconv"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/falcosecurity/falcosidekick/types"
)

// Some constant strings to use in request headers
const FissionEventIDKey = "event-id"
const FissionEventTypeKey = "event-type"
const FissionEventNamespaceKey = "event-namespace"
const FissionEventTypeValue = "falco"
const FissionContentType = "application/json"

// NewFissionClient returns a new output.Client for accessing Kubernetes.
func NewFissionClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	if config.Fission.KubeConfig != "" {
		restConfig, err := clientcmd.BuildConfigFromFlags("", config.Fission.KubeConfig)
		if err != nil {
			return nil, err
		}
		clientset, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return &Client{
			OutputType:       "Fission",
			Config:           config,
			Stats:            stats,
			PromStats:        promStats,
			StatsdClient:     statsdClient,
			DogstatsdClient:  dogstatsdClient,
			KubernetesClient: clientset,
		}, nil
	}
	return NewClient(
		"Fission",
		"http://"+config.Fission.Function+"."+config.Fission.Namespace+".svc.cluster.local:"+strconv.Itoa(config.Fission.Port),
		config.Fission.MutualTLS,
		config.Fission.CheckCert,
		config,
		stats,
		promStats,
		statsdClient,
		dogstatsdClient,
	)
}

// FissionCall .
func (c *Client) FissionCall(falcopayload types.FalcoPayload) {
	c.Stats.Fission.Add(Total, 1)

	if c.Config.Fission.KubeConfig != "" {
		str, _ := json.Marshal(falcopayload)
		req := c.KubernetesClient.CoreV1().RESTClient().Post().AbsPath("/api/v1/namespaces/" + c.Config.Fission.Namespace + "/services/" + c.Config.Fission.Function + ":" + strconv.Itoa(c.Config.Fission.Port) + "/proxy/").Body(str)
		req.SetHeader(FissionEventIDKey, uuid.New().String())
		req.SetHeader(ContentTypeHeaderKey, FissionContentType)
		req.SetHeader(UserAgentHeaderKey, UserAgentHeaderValue)
		req.SetHeader(FissionEventTypeKey, FissionEventTypeValue)
		req.SetHeader(FissionEventNamespaceKey, c.Config.Fission.Namespace)

		res := req.Do(context.TODO())
		rawbody, err := res.Raw()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:Fission", "status:error"})
			c.Stats.Fission.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "Fission", "status": Error}).Inc()
			log.Printf("[ERROR] : Fission - %v\n", err)
			return
		}
		log.Printf("[INFO]  : Fission - Function Response : %v\n", string(rawbody))
	} else {
		c.AddHeader(FissionEventIDKey, uuid.New().String())
		c.AddHeader(FissionEventTypeKey, FissionEventTypeValue)
		c.AddHeader(FissionEventNamespaceKey, c.Config.Fission.Namespace)
		c.ContentType = FissionContentType

		err := c.Post(falcopayload)
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:Fission", "status:error"})
			c.Stats.Fission.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "Fission", "status": Error}).Inc()
			log.Printf("[ERROR] : Fission - %v\n", err)
			return
		}
	}
	log.Printf("[INFO]  : Fission - Call Function \"%v\" OK\n", c.Config.Fission.Function)
	go c.CountMetric(Outputs, 1, []string{"output:Fission", "status:ok"})
	c.Stats.Fission.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "Fission", "status": OK}).Inc()
}

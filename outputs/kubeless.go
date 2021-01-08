package outputs

import (
	"context"
	"encoding/json"
	"log"
	"strconv"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NewKubelessClient returns a new output.Client for accessing Kubernetes.
func NewKubelessClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	if config.Kubeless.Kubeconfig != "" {
		restConfig, err := clientcmd.BuildConfigFromFlags("", config.Kubeless.Kubeconfig)
		if err != nil {
			return nil, err
		}
		clientset, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return &Client{
			OutputType:       "Kubeless",
			Config:           config,
			Stats:            stats,
			PromStats:        promStats,
			StatsdClient:     statsdClient,
			DogstatsdClient:  dogstatsdClient,
			KubernetesClient: clientset,
		}, nil
	}
	return NewClient(
		"Kubeless",
		"http://"+config.Kubeless.Function+"."+config.Kubeless.Namespace+".svc.cluster.local:"+strconv.Itoa(config.Kubeless.Port),
		config,
		stats,
		promStats,
		statsdClient,
		dogstatsdClient,
	)
}

// KubelessCall .
func (c *Client) KubelessCall(falcopayload types.FalcoPayload) {
	c.Stats.Kubeless.Add(Total, 1)

	if c.Config.Kubeless.Kubeconfig != "" {
		str, _ := json.Marshal(falcopayload)
		req := c.KubernetesClient.CoreV1().RESTClient().Post().AbsPath("/api/v1/namespaces/" + c.Config.Kubeless.Namespace + "/services/" + c.Config.Kubeless.Function + ":" + strconv.Itoa(c.Config.Kubeless.Port) + "/proxy/").Body(str)
		req.SetHeader("event-id", uuid.New().String())
		req.SetHeader("Content-Type", "application/json")
		req.SetHeader("User-Agent", "Falcosidekick")
		req.SetHeader("event-type", "falco")
		req.SetHeader("event-namespace", c.Config.Kubeless.Namespace)

		res := req.Do(context.TODO())
		rawbody, err := res.Raw()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:error"})
			c.Stats.Kubeless.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": Error}).Inc()
			log.Printf("[ERROR] : Kubeless - %v\n", err)
			return
		}
		log.Printf("[INFO]  : Kubeless - Function Response : %v\n", string(rawbody))
	} else {
		err := c.Post(falcopayload)
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:error"})
			c.Stats.Kubeless.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": Error}).Inc()
			log.Printf("[ERROR] : Kubeless - %v\n", err)
			return
		}
	}
	log.Printf("[INFO]  : Kubeless - Call Function \"%v\" OK\n", c.Config.Kubeless.Function)
	go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:ok"})
	c.Stats.Kubeless.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": OK}).Inc()
}

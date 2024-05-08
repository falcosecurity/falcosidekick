// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewOpenfaasClient returns a new output.Client for accessing Kubernetes.
func NewOpenfaasClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	if config.Openfaas.Kubeconfig != "" {
		restConfig, err := clientcmd.BuildConfigFromFlags("", config.Openfaas.Kubeconfig)
		if err != nil {
			return nil, err
		}
		clientset, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return &Client{
			OutputType:       Openfaas,
			Config:           config,
			Stats:            stats,
			PromStats:        promStats,
			StatsdClient:     statsdClient,
			DogstatsdClient:  dogstatsdClient,
			KubernetesClient: clientset,
		}, nil
	}

	endpointUrl := fmt.Sprintf("http://%s.%s:%d/function/%s.%s", config.Openfaas.GatewayService, config.Openfaas.GatewayNamespace, config.Openfaas.GatewayPort, config.Openfaas.FunctionName, config.Openfaas.FunctionNamespace)
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
	}

	return NewClient(Openfaas, endpointUrl, config.Openfaas.MutualTLS, config.Openfaas.CheckCert, *initClientArgs)
}

// OpenfaasCall .
func (c *Client) OpenfaasCall(falcopayload types.FalcoPayload) {
	c.Stats.Openfaas.Add(Total, 1)

	if c.Config.Openfaas.Kubeconfig != "" {
		str, _ := json.Marshal(falcopayload)
		req := c.KubernetesClient.CoreV1().RESTClient().Post().AbsPath("/api/v1/namespaces/" + c.Config.Openfaas.GatewayNamespace + "/services/" + c.Config.Openfaas.GatewayService + ":" + strconv.Itoa(c.Config.Openfaas.GatewayPort) + "/proxy" + "/function/" + c.Config.Openfaas.FunctionName + "." + c.Config.Openfaas.FunctionNamespace).Body(str)
		req.SetHeader("event-id", uuid.New().String())
		req.SetHeader("Content-Type", "application/json")
		req.SetHeader("User-Agent", "Falcosidekick")

		res := req.Do(context.TODO())
		rawbody, err := res.Raw()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:openfaas", "status:error"})
			c.Stats.Openfaas.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "openfaas", "status": Error}).Inc()
			log.Printf("[ERROR] : %v - %v\n", Openfaas, err)
			return
		}
		log.Printf("[INFO]  : %v - Function Response : %v\n", Openfaas, string(rawbody))
	} else {
		err := c.Post(falcopayload)
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:openfaas", "status:error"})
			c.Stats.Openfaas.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "openfaas", "status": Error}).Inc()
			log.Printf("[ERROR] : %v - %v\n", Openfaas, err)
			return
		}
	}
	log.Printf("[INFO]  : %v - Call Function \"%v\" OK\n", Openfaas, c.Config.Openfaas.FunctionName+"."+c.Config.Openfaas.FunctionNamespace)
	go c.CountMetric(Outputs, 1, []string{"output:openfaas", "status:ok"})
	c.Stats.Openfaas.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openfaas", "status": OK}).Inc()
}

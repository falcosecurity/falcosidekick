// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// Some constant strings to use in request headers
const KubelessEventIDKey = "event-id"
const KubelessUserAgentKey = "User-Agent"
const KubelessEventTypeKey = "event-type"
const KubelessEventNamespaceKey = "event-namespace"
const KubelessEventTypeValue = "falco"
const KubelessContentType = "application/json"

// NewKubelessClient returns a new output.Client for accessing Kubernetes.
func NewKubelessClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
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
			OTLPMetrics:      otlpMetrics,
			StatsdClient:     statsdClient,
			DogstatsdClient:  dogstatsdClient,
			KubernetesClient: clientset,
			cfg:              config.Kubeless.CommonConfig,
		}, nil
	}

	endpointUrl := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", config.Kubeless.Function, config.Kubeless.Namespace, config.Kubeless.Port)
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
	}

	return NewClient("Kubeless", endpointUrl, config.Kubeless.CommonConfig, *initClientArgs)
}

// KubelessCall .
func (c *Client) KubelessCall(falcopayload types.FalcoPayload) {
	c.Stats.Kubeless.Add(Total, 1)

	if c.Config.Kubeless.Kubeconfig != "" {
		str, _ := json.Marshal(falcopayload)
		req := c.KubernetesClient.CoreV1().RESTClient().Post().AbsPath("/api/v1/namespaces/" + c.Config.Kubeless.Namespace + "/services/" + c.Config.Kubeless.Function + ":" + strconv.Itoa(c.Config.Kubeless.Port) + "/proxy/").Body(str)
		req.SetHeader(KubelessEventIDKey, uuid.New().String())
		req.SetHeader(ContentTypeHeaderKey, KubelessContentType)
		req.SetHeader(UserAgentHeaderKey, UserAgentHeaderValue)
		req.SetHeader(KubelessEventTypeKey, KubelessEventTypeValue)
		req.SetHeader(KubelessEventNamespaceKey, c.Config.Kubeless.Namespace)

		res := req.Do(context.TODO())
		rawbody, err := res.Raw()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:error"})
			c.Stats.Kubeless.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": Error}).Inc()
			c.OTLPMetrics.Outputs.With(attribute.String("destination", "kubeless"),
				attribute.String("status", Error)).Inc()
			utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
			return
		}
		utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("Function Response : %v", string(rawbody)))
	} else {
		c.ContentType = KubelessContentType

		err := c.Post(falcopayload, func(req *http.Request) {
			req.Header.Set(KubelessEventIDKey, uuid.New().String())
			req.Header.Set(KubelessEventTypeKey, KubelessEventTypeValue)
			req.Header.Set(KubelessEventNamespaceKey, c.Config.Kubeless.Namespace)
		})
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:error"})
			c.Stats.Kubeless.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": Error}).Inc()
			c.OTLPMetrics.Outputs.With(attribute.String("destination", "kubeless"),
				attribute.String("status", Error)).Inc()
			utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
			return
		}
	}
	utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("Call Function \"%v\" OK", c.Config.Kubeless.Function))
	go c.CountMetric(Outputs, 1, []string{"output:kubeless", "status:ok"})
	c.Stats.Kubeless.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "kubeless", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "kubeless"),
		attribute.String("status", OK)).Inc()
}

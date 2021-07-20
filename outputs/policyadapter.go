package outputs

import (
	"context"
	"fmt"

	clusterpolicyreport "github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	crdClient "github.com/anushkamittal20/falcoadapter/pkg/generated/v1alpha2/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	//"log"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	"github.com/falcosecurity/falcosidekick/types"
	"k8s.io/client-go/tools/clientcmd"
	// "github.com/google/uuid"
)

func NewPolicyReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	if config.PolicyReport.Kubeconfig != "" {
		restConfig, err := clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("unable to load kube config file: %v", err)
		}
		clientset, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return &Client{
			OutputType:       "PolicyReport",
			Config:           config,
			Stats:            stats,
			PromStats:        promStats,
			StatsdClient:     statsdClient,
			DogstatsdClient:  dogstatsdClient,
			KubernetesClient: clientset,
		}, nil
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to load in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		OutputType:       "PolicyReport",
		Config:           config,
		Stats:            stats,
		PromStats:        promStats,
		StatsdClient:     statsdClient,
		DogstatsdClient:  dogstatsdClient,
		KubernetesClient: clientset,
	}, nil

}

// PolicyReportPost creates Policy Report Resource in Kubernetes
func (c *Client) PolicyReportCreate(falcopayload types.FalcoPayload) {
	//to do
	var crdclient *crdClient.Clientset
	if c.Config.PolicyReport.Kubeconfig != "" {
		restConfig, err := clientcmd.BuildConfigFromFlags("", c.Config.PolicyReport.Kubeconfig)
		if err != nil {
			fmt.Printf("unable to load kube config file: %v", err)
		}
		crdclient, err = crdClient.NewForConfig(restConfig)
		if err != nil {
			fmt.Printf("u %v", err)
		}
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("unable to load in-cluster config: %v", err)
	}

	crdclient, err = crdClient.NewForConfig(restConfig)
	if err != nil {
		fmt.Printf("u %v", err)
	}
	ats := crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()
	report := &clusterpolicyreport.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dummy-policy-report",
		},
		Summary: v1alpha2.PolicyReportSummary{
			//Fail: len(controls.Alert),
		},
	}
	report.Results = append(report.Results, newResult(falcopayload))
	result, err := ats.Create(context.TODO(), report, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created policy-report %q.\n", result.GetObjectMeta().GetName())
}

func newResult(FalcoPayload types.FalcoPayload) *clusterpolicyreport.PolicyReportResult {
	const PolicyReportSource string = "Falco"
	var pri string
	if FalcoPayload.Priority > 4 {
		pri = "high"
	} else if FalcoPayload.Priority < 3 {
		pri = "low"
	} else {
		pri = "medium"
	}
	var m = make(map[string]string)
	for index, element := range FalcoPayload.OutputFields {
		m[index] = fmt.Sprintf("%v", element)
	}
	return &clusterpolicyreport.PolicyReportResult{
		Policy:      FalcoPayload.Rule,
		Source:      PolicyReportSource,
		Scored:      false,
		Timestamp:   metav1.Timestamp{Seconds: int64(FalcoPayload.Time.Second()), Nanos: int32(FalcoPayload.Time.Nanosecond())},
		Severity:    v1alpha2.PolicyResultSeverity(pri),
		Result:      "fail",
		Description: FalcoPayload.Output,
		Properties:  m,
	}
}

package outputs

import (
	"context"
	"fmt"
	"log"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	clusterpolicyreport "github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	crdClient "github.com/anushkamittal20/falcoadapter/pkg/generated/v1alpha2/clientset/versioned"
	"github.com/falcosecurity/falcosidekick/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewPolicyReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		restConfig, err = clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			fmt.Printf("[ERROR] :unable to load kube config file: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	crdclient, err := crdClient.NewForConfig(restConfig)
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
		Crdclient:        crdclient,
	}, nil

}

// PolicyReportPost creates Policy Report Resource in Kubernetes
func (c *Client) PolicyReportCreate(falcopayload types.FalcoPayload) {
	ats := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()
	report := &clusterpolicyreport.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dummy-policy-report",
		},
		Summary: v1alpha2.PolicyReportSummary{
			Fail: 1, //hardcoded for time being; to-do
		},
	}
	report.Results = append(report.Results, newResult(falcopayload))

	_, getErr := ats.Get(context.Background(), report.Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := ats.Create(context.TODO(), report, metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : %v\n", err)
		}
		fmt.Printf("[INFO] :Created policy-report %q.\n", result.GetObjectMeta().GetName())
	} else {
		// Update existing Policy Report
		fmt.Println("[INFO] :updating policy report...")
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {

			result, err := ats.Get(context.Background(), report.GetName(), metav1.GetOptions{})
			if errors.IsNotFound(err) {
				// This doesnt ever happen even if it is already deleted or not found
				log.Printf("[ERROR] :%v not found", report.GetName())
				return nil
			}

			if err != nil {
				return err
			}

			report.SetResourceVersion(result.GetResourceVersion())

			_, updateErr := ats.Update(context.Background(), report, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			fmt.Printf("[ERROR] :update failed: %v", retryErr)
		}
		fmt.Println("[INFO] :updated policy report...")
	}
}

//mapping for the policy report
func newResult(FalcoPayload types.FalcoPayload) *clusterpolicyreport.PolicyReportResult {
	const PolicyReportSource string = "Falco"
	var pri string //initial hardcoded priority bounds
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

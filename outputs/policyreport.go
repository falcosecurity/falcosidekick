package outputs

import (
	"context"
	"fmt"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	"github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	wgpolicy "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	crdClient "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/generated/v1alpha2/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	clusterPolicyReportBaseName = "falco-cluster-policy-report-"
	policyReportBaseName        = "falco-policy-report-"
	policyReportSource          = "Falco"
	highpriority                = "high"
	lowpriority                 = "low"
	mediumpriority              = "medium"
)

var (
	minimumPriority string
	severity        string
	result          string
	//slice of policy reports
	policyReports = make(map[string]*wgpolicy.PolicyReport)
	//cluster policy report
	clusterPolicyReport *wgpolicy.ClusterPolicyReport = &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterPolicyReportBaseName,
		},
		Summary: v1alpha2.PolicyReportSummary{
			Fail: 0,
			Warn: 0,
		},
	}
)

func NewPolicyReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	clusterPolicyReport.ObjectMeta.Name += uuid.NewString()[:8]
	minimumPriority = config.PolicyReport.MinimumPriority

	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		clientConfig, err = clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Unable to load kube config file: %v\n", err)
		}
	}
	crdclient, err := crdClient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		OutputType:      "PolicyReport",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		Crdclient:       crdclient,
	}, nil
}

// UpdateOrCreatePolicyReport creates/updates PolicyReport/ClusterPolicyReport Resource in Kubernetes
func (c *Client) UpdateOrCreatePolicyReport(falcopayload types.FalcoPayload) {
	c.Stats.PolicyReport.Add(Total, 1)

	event, namespace := newResult(falcopayload)

	var err error
	if namespace != "" {
		// case where the event is namespace specific
		err = updatePolicyReports(c, namespace, event)
	} else {
		err = updateClusterPolicyReport(c, event)
	}
	if err == nil {
		go c.CountMetric(Outputs, 1, []string{"output:policyreport", "status:ok"})
		c.Stats.PolicyReport.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "policyreport", "status": OK}).Inc()
	} else {
		go c.CountMetric(Outputs, 1, []string{"output:policyreport", "status:error"})
		c.Stats.PolicyReport.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "policyreport", "status": Error}).Inc()
	}
}

//newResult creates a new entry for Reports
func newResult(FalcoPayload types.FalcoPayload) (_ *wgpolicy.PolicyReportResult, namespace string) {
	var properties = make(map[string]string)
	for property, value := range FalcoPayload.OutputFields {
		if property == "ka.target.namespace" || property == "k8s.ns.name" {
			namespace = fmt.Sprintf("%v", value) // not empty for policy reports
		}
		properties[property] = fmt.Sprintf("%v", value)
	}
	if FalcoPayload.Priority > types.Priority(minimumPriority) {
		severity = highpriority
		result = "fail"
	} else if FalcoPayload.Priority < types.Priority(minimumPriority) {
		severity = lowpriority
		result = "warn"
	} else {
		severity = mediumpriority
		result = "warn"
	}

	return &wgpolicy.PolicyReportResult{
		Policy:      FalcoPayload.Rule,
		Category:    "SI - System and Information Integrity",
		Source:      policyReportSource,
		Scored:      false,
		Timestamp:   metav1.Timestamp{Seconds: int64(FalcoPayload.Time.Second()), Nanos: int32(FalcoPayload.Time.Nanosecond())},
		Severity:    v1alpha2.PolicyResultSeverity(severity),
		Result:      v1alpha2.PolicyResult(result),
		Description: FalcoPayload.Output,
		Properties:  properties,
	}, namespace
}

//check for low priority events to delete first
func checklow(result []*wgpolicy.PolicyReportResult) (swapint int) {
	for i, j := range result {
		if j.Severity == mediumpriority || j.Severity == lowpriority {
			return i
		}
	}
	return -1
}

//update summary for clusterpolicyreport 'report'
func updateClusterPolicyReportSummary(event *wgpolicy.PolicyReportResult) {
	if event.Result == "fail" {
		clusterPolicyReport.Summary.Fail++
	} else {
		clusterPolicyReport.Summary.Warn++
	}
}

//update summary for specific policyreport in 'policyReports' at index 'n'
func updatePolicyReportSummary(rep *wgpolicy.PolicyReport, event *wgpolicy.PolicyReportResult) {
	if event.Result == "fail" {
		rep.Summary.Fail++
	} else {
		rep.Summary.Warn++
	}
}

func updatePolicyReports(c *Client, namespace string, event *wgpolicy.PolicyReportResult) error {
	//policyReport to be created
	if policyReports[namespace] == nil {
		policyReports[namespace] = &wgpolicy.PolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyReportBaseName + uuid.NewString()[:8],
			},
			Summary: v1alpha2.PolicyReportSummary{
				Fail: 0,
				Warn: 0,
			},
		}
	}

	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	updatePolicyReportSummary(policyReports[namespace], event)
	if len(policyReports[namespace].Results) == c.Config.PolicyReport.MaxEvents {
		if c.Config.PolicyReport.PruneByPriority == true {
			pruningLogicForPolicyReports(namespace)
		} else {
			if policyReports[namespace].Results[0].Severity == highpriority {
				summaryDeletion(policyReports[namespace], true)
			} else {
				summaryDeletion(policyReports[namespace], false)
			}
			policyReports[namespace].Results = policyReports[namespace].Results[1:]
		}
	}
	policyReports[namespace].Results = append(policyReports[namespace].Results, event)
	_, getErr := policyr.Get(context.Background(), policyReports[namespace].Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := policyr.Create(context.TODO(), policyReports[namespace], metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : Can't create Policy Report %v in namespace %v\n", err, namespace)
			return err
		}
		log.Printf("[INFO]  : PolicyReport - Create policy report %v in namespace %v\n", result.GetObjectMeta().GetName(), namespace)

	} else {
		// Update existing Policy Report
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			result, err := policyr.Get(context.Background(), policyReports[namespace].GetName(), metav1.GetOptions{})
			if errors.IsNotFound(err) {
				// This doesnt ever happen even if it is already deleted or not found
				log.Printf("[ERROR] : PolicyReport - Policy Report %v not found in namespace %v\n", policyReports[namespace].GetName(), namespace)
				return err
			}
			if err != nil {
				log.Printf("[ERROR] : PolicyReport - Policy Report %v in namespace %v: %v\n", policyReports[namespace].GetName(), namespace, err)
				return err
			}
			policyReports[namespace].SetResourceVersion(result.GetResourceVersion())
			_, updateErr := policyr.Update(context.Background(), policyReports[namespace], metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			log.Printf("[ERROR] : PolicyReport - Update has failed for Policy Report %v in namespace %v: %v\n", policyReports[namespace].GetName(), namespace, retryErr)
			return retryErr
		}
		log.Printf("[INFO]  : PolicyReport - Policy Report %v in namespace %v has been updated\n", policyReports[namespace].GetName(), namespace)
	}
	return nil
}

func updateClusterPolicyReport(c *Client, event *wgpolicy.PolicyReportResult) error {
	updateClusterPolicyReportSummary(event)
	//clusterpolicyreport to be created
	clusterpr := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()

	if len(clusterPolicyReport.Results) == c.Config.PolicyReport.MaxEvents {
		if c.Config.PolicyReport.PruneByPriority == true {
			pruningLogicForClusterPolicyReport()
		} else {
			if clusterPolicyReport.Results[0].Severity == highpriority {
				summaryDeletionCluster(clusterPolicyReport, true)
			} else {
				summaryDeletionCluster(clusterPolicyReport, false)
			}
			clusterPolicyReport.Results[0] = nil
			clusterPolicyReport.Results = clusterPolicyReport.Results[1:]
		}
	}

	clusterPolicyReport.Results = append(clusterPolicyReport.Results, event)

	_, getErr := clusterpr.Get(context.Background(), clusterPolicyReport.Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := clusterpr.Create(context.TODO(), clusterPolicyReport, metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - %v\n", err)
			return err
		}
		log.Printf("[INFO]  : PolicyReport - Create Cluster Policy Report %v\n", result.GetObjectMeta().GetName())
	} else {
		// Update existing Cluster Policy Report
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			result, err := clusterpr.Get(context.Background(), clusterPolicyReport.GetName(), metav1.GetOptions{})
			if errors.IsNotFound(err) {
				// This doesnt ever happen even if it is already deleted or not found
				log.Printf("[ERROR] : PolicyReport - Cluster Policy Report %v not found\n", clusterPolicyReport.GetName())
				return err
			}
			if err != nil {
				log.Printf("[ERROR] : PolicyReport - Cluster Policy Report %v: %v\n", clusterPolicyReport.GetName(), err)
				return err
			}
			clusterPolicyReport.SetResourceVersion(result.GetResourceVersion())
			_, updateErr := clusterpr.Update(context.Background(), clusterPolicyReport, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			log.Printf("[ERROR] : PolicyReport - Update has failed for Cluster Policy Report %v: %v\n", clusterPolicyReport.GetName(), retryErr)
			return retryErr
		}
		log.Printf("[INFO]  : PolicyReport - Cluster Policy Report %v has been updated\n", clusterPolicyReport.GetName())
	}
	return nil
}

func pruningLogicForPolicyReports(namespace string) {
	//To do for pruning for pruning one of policyreports
	checklowvalue := checklow(policyReports[namespace].Results)
	if checklowvalue > 0 {
		policyReports[namespace].Results[checklowvalue] = policyReports[namespace].Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletion(policyReports[namespace], true)
	} else {
		summaryDeletion(policyReports[namespace], false)
	}
	policyReports[namespace].Results[0] = nil
	policyReports[namespace].Results = policyReports[namespace].Results[1:]
}

func pruningLogicForClusterPolicyReport() {
	//To do for pruning cluster report
	checklowvalue := checklow(clusterPolicyReport.Results)
	if checklowvalue > 0 {
		clusterPolicyReport.Results[checklowvalue] = clusterPolicyReport.Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletionCluster(clusterPolicyReport, true)
	} else {
		summaryDeletionCluster(clusterPolicyReport, false)
	}
	clusterPolicyReport.Results[0] = nil
	clusterPolicyReport.Results = clusterPolicyReport.Results[1:]
}

func summaryDeletionCluster(rep *wgpolicy.ClusterPolicyReport, deleteFailevent bool) {
	if deleteFailevent == true {
		rep.Summary.Fail--
	} else {
		rep.Summary.Warn--
	}
}

func summaryDeletion(rep *wgpolicy.PolicyReport, deleteFailevent bool) {
	if deleteFailevent == true {
		rep.Summary.Fail--
	} else {
		rep.Summary.Warn--
	}
}

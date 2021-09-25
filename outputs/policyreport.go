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

//for n namespace specific reports with their count
type pr struct {
	report *wgpolicy.PolicyReport
	count  int
}

const (
	clusterPolicyReportBaseName = "falco-cluster-policy-report-"
	policyReportSource          = "Falco"
	highpriority                = "high"
)

var (
	failThreshold int
	//count for cluster policy report
	repcount int
	//slice of policyreports and their counts(type pr)
	polreports = make(map[string]*pr)
	//for cluster policyreport
	report *wgpolicy.ClusterPolicyReport = &wgpolicy.ClusterPolicyReport{
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
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		clientConfig, err = clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - unable to load kube config file: %v\n", err)
		}
	}
	crdclient, err := crdClient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	report.ObjectMeta.Name += uuid.NewString()[:8]
	failThreshold = config.PolicyReport.FailThreshold
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

// CreateReport creates PolicyReport/ClusterPolicyReport Resource in Kubernetes
func (c *Client) CreateReport(falcopayload types.FalcoPayload) {
	alert, namespaceScoped := newResult(falcopayload)
	if namespaceScoped != "" {
		forPolicyReports(c, namespaceScoped, alert)
	} else {
		forClusterPolicyReport(c, alert)
	}
}

//newResult creates a new entry for Reports
func newResult(FalcoPayload types.FalcoPayload) (c *wgpolicy.PolicyReportResult, namespaceScoped string) {
	var m = make(map[string]string)
	for index, element := range FalcoPayload.OutputFields {
		if index == "ka.target.namespace" || index == "k8s.ns.name" {
			namespaceScoped = fmt.Sprintf("%v", element) // not empty for policy reports

		}
		m[index] = fmt.Sprintf("%v", element)
	}
	var pri string //initial hardcoded priority bounds
	if FalcoPayload.Priority > types.PriorityType(failThreshold) {
		pri = highpriority
	} else if FalcoPayload.Priority < types.PriorityType(failThreshold) {
		pri = "low"
	} else {
		pri = "medium"
	}
	return &wgpolicy.PolicyReportResult{
		Policy:      FalcoPayload.Rule,
		Category:    "SI - System and Information Integrity",
		Source:      policyReportSource,
		Scored:      false,
		Timestamp:   metav1.Timestamp{Seconds: int64(FalcoPayload.Time.Second()), Nanos: int32(FalcoPayload.Time.Nanosecond())},
		Severity:    v1alpha2.PolicyResultSeverity(pri),
		Result:      "fail",
		Description: FalcoPayload.Output,
		Properties:  m,
	}, namespaceScoped
}

//check for low priority events to delete first
func checklow(result []*wgpolicy.PolicyReportResult) (swapint int) {
	for i, j := range result {
		if j.Severity == "medium" || j.Severity == "low" {
			return i
		}
	}
	return -1
}

//check if policy report exists
func repexist(ns string) bool {
	_, ok := polreports[ns]
	return ok
}

//update summary for clusterpolicyreport 'report'
func updateClusterSummary(alert *wgpolicy.PolicyReportResult) {
	if alert.Severity == highpriority {
		report.Summary.Fail++
	} else {
		report.Summary.Warn++
	}
}

//update summary for specific policyreport in 'polreports' at index 'n'
func updatePolicyReportSummary(rep *wgpolicy.PolicyReport, alert *wgpolicy.PolicyReportResult) {
	if alert.Severity == highpriority {
		rep.Summary.Fail++
	} else {
		rep.Summary.Warn++
	}
}

func forPolicyReports(c *Client, namespace string, alert *wgpolicy.PolicyReportResult) {
	//find if the specific namespace report exists and assign its index to n
	n := repexist(namespace)
	//policyreport to be created
	if n == false {
		//n false ; report doesnt exist so we append a new report to the slice
		var polreport *wgpolicy.PolicyReport = &wgpolicy.PolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "falco-report-" + uuid.NewString()[:8],
			},
			Summary: v1alpha2.PolicyReportSummary{
				Fail: 0,
				Warn: 0,
			},
		}
		toappend := pr{report: polreport, count: 0}
		polreports[namespace] = &toappend
	}
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	updatePolicyReportSummary(polreports[namespace].report, alert)
	polreports[namespace].count++
	if polreports[namespace].count > c.Config.PolicyReport.MaxEvents {
		if c.Config.PolicyReport.PruneByPriority == true {
			pruningLogicForPolicyReports(namespace)
		} else {
			if polreports[namespace].report.Results[0].Severity == highpriority {
				summaryDeletion(polreports[namespace].report, true)
			} else {
				summaryDeletion(polreports[namespace].report, false)
			}
			polreports[namespace].report.Results[0] = nil
			polreports[namespace].report.Results = polreports[namespace].report.Results[1:]
			polreports[namespace].count = polreports[namespace].count - 1
		}
	}
	polreports[namespace].report.Results = append(polreports[namespace].report.Results, alert)
	_, getErr := policyr.Get(context.Background(), polreports[namespace].report.Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := policyr.Create(context.TODO(), polreports[namespace].report, metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - %v\n", err)
		}
		log.Printf("[INFO] : PolicyReport - Created policy-report %q in namespace: %v.\n", result.GetObjectMeta().GetName(), namespace)

	} else {
		// Update existing Policy Report
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			result, err := policyr.Get(context.Background(), polreports[namespace].report.GetName(), metav1.GetOptions{})
			if errors.IsNotFound(err) {
				// This doesnt ever happen even if it is already deleted or not found
				log.Printf("[ERROR] : PolicyReport - %v not found", polreports[namespace].report.GetName())
				return nil
			}
			if err != nil {
				return err
			}
			polreports[namespace].report.SetResourceVersion(result.GetResourceVersion())
			_, updateErr := policyr.Update(context.Background(), polreports[namespace].report, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			log.Printf("[ERROR] : PolicyReport - Update has failed: %v", retryErr)

		}
		log.Printf("[INFO] : PolicyReport - Policy report has been updated")
	}
}

func forClusterPolicyReport(c *Client, alert *wgpolicy.PolicyReportResult) {
	updateClusterSummary(alert)
	//clusterpolicyreport to be created
	clusterpr := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()

	repcount++
	if repcount > c.Config.PolicyReport.MaxEvents {
		//To do for pruning
		if c.Config.PolicyReport.PruneByPriority == true {
			pruningLogicForClusterReport()
		} else {
			if report.Results[0].Severity == highpriority {
				summaryDeletionCluster(report, true)
			} else {
				summaryDeletionCluster(report, false)
			}
			report.Results[0] = nil
			report.Results = report.Results[1:]
			repcount = repcount - 1
		}
	}
	report.Results = append(report.Results, alert)
	_, getErr := clusterpr.Get(context.Background(), report.Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := clusterpr.Create(context.TODO(), report, metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - %v\n", err)
		}
		log.Printf("[INFO] : PolicyReport - Created cluster-policy-report %q.\n", result.GetObjectMeta().GetName())
	} else {
		// Update existing Cluster Policy Report
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			result, err := clusterpr.Get(context.Background(), report.GetName(), metav1.GetOptions{})
			if errors.IsNotFound(err) {
				// This doesnt ever happen even if it is already deleted or not found
				log.Printf("[ERROR] : PolicyReport - %v not found", report.GetName())
				return nil
			}
			if err != nil {
				return err
			}
			report.SetResourceVersion(result.GetResourceVersion())
			_, updateErr := clusterpr.Update(context.Background(), report, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			log.Printf("[ERROR] : PolicyReport - Update has failed: %v", retryErr)
		}
		log.Printf("[INFO] : PolicyReport - Cluster policy report has been updated")

	}
}

func pruningLogicForPolicyReports(ns string) {
	//To do for pruning for pruning one of policyreports
	checklowvalue := checklow(polreports[ns].report.Results)
	if checklowvalue > 0 {
		polreports[ns].report.Results[checklowvalue] = polreports[ns].report.Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletion(polreports[ns].report, true)
	} else {
		summaryDeletion(polreports[ns].report, false)
	}
	polreports[ns].report.Results[0] = nil
	polreports[ns].report.Results = polreports[ns].report.Results[1:]
	polreports[ns].count = polreports[ns].count - 1
}

func pruningLogicForClusterReport() {
	//To do for pruning cluster report
	checklowvalue := checklow(report.Results)
	if checklowvalue > 0 {
		report.Results[checklowvalue] = report.Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletionCluster(report, true)
	} else {
		summaryDeletionCluster(report, false)
	}
	report.Results[0] = nil
	report.Results = report.Results[1:]
	repcount = repcount - 1
}

func summaryDeletionCluster(rep *wgpolicy.ClusterPolicyReport, faildel bool) {
	if faildel == true {
		rep.Summary.Fail--
	} else {
		rep.Summary.Warn--
	}
}

func summaryDeletion(rep *wgpolicy.PolicyReport, faildel bool) {
	if faildel == true {
		rep.Summary.Fail--
	} else {
		rep.Summary.Warn--
	}
}

// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
	crdClient "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned"
)

type resource struct {
	apiVersion string
	kind       string
}

const (
	clusterPolicyReportBaseName = "falco-cluster-policy-report-"
	policyReportBaseName        = "falco-policy-report-"
	policyReportSource          = "Falco"

	high     wgpolicy.PolicyResultSeverity = "high"
	low      wgpolicy.PolicyResultSeverity = "low"
	medium   wgpolicy.PolicyResultSeverity = "medium"
	info     wgpolicy.PolicyResultSeverity = "info"
	critical wgpolicy.PolicyResultSeverity = "critical"

	fail wgpolicy.PolicyResult = "fail"
	warn wgpolicy.PolicyResult = "warn"
	skip wgpolicy.PolicyResult = "skip"

	targetNS       = "ka.target.namespace"
	targetResource = "ka.target.resource"
	targetName     = "ka.target.name"
	responseName   = "ka.resp.name"
)

var (
	minimumPriority string //nolint: unused
	//slice of policy reports
	policyReports = make(map[string]*wgpolicy.PolicyReport)
	//cluster policy report
	clusterPolicyReport *wgpolicy.ClusterPolicyReport = &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterPolicyReportBaseName,
			Labels: map[string]string{
				"app.kubernetes.io/created-by": "falcosidekick",
			},
		},
		Summary: wgpolicy.PolicyReportSummary{
			Fail: 0,
			Warn: 0,
		},
	}
	falcosidekickNamespace    string
	falcosidekickNamespaceUID k8stypes.UID

	// used resources in the k8saudit ruleset
	resourceMapping = map[string]resource{
		"pods":                {"v1", "Pod"},
		"services":            {"v1", "Service"},
		"secrets":             {"v1", "Secrets"},
		"configmaps":          {"v1", "ConfigMap"},
		"namespaces":          {"v1", "Namespace"},
		"serviceaccounts":     {"v1", "ServiceAccount"},
		"daemonsets":          {"apps/v1", "DaemonSet"},
		"deployments":         {"apps/v1", "Deployments"},
		"cronjobs":            {"batch/v1", "CronJob"},
		"jobs":                {"batch/v1", "Job"},
		"clusterroles":        {"rbac.authorization.k8s.io/v1", "ClusterRole"},
		"clusterrolebindings": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},
		"roles":               {"rbac.authorization.k8s.io/v1", "Role"},
		"rolebindings":        {"rbac.authorization.k8s.io/v1", "RoleBinding"},
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
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	falcosidekickNamespace = os.Getenv("NAMESPACE")
	if falcosidekickNamespace == "" {
		log.Println("[INFO]  : PolicyReport - No env var NAMESPACE detected")
	} else {
		n, err := clientset.CoreV1().Namespaces().Get(context.TODO(), falcosidekickNamespace, metav1.GetOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Can't get UID of namespace %v: %v\n", falcosidekickNamespace, err)
		} else {
			falcosidekickNamespaceUID = n.ObjectMeta.UID
		}
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

// newResult creates a new entry for Reports
func newResult(falcopayload types.FalcoPayload) (_ *wgpolicy.PolicyReportResult, namespace string) {
	var properties = make(map[string]string)
	for property, value := range falcopayload.OutputFields {
		if property == targetNS || property == "k8s.ns.name" {
			namespace = toString(value) // not empty for policy reports
		}
		properties[property] = toString(value)
	}

	return &wgpolicy.PolicyReportResult{
		Policy:      falcopayload.Rule,
		Category:    "SI - System and Information Integrity",
		Source:      policyReportSource,
		Scored:      false,
		Timestamp:   metav1.Timestamp{Seconds: int64(falcopayload.Time.Second()), Nanos: int32(falcopayload.Time.Nanosecond())},
		Severity:    mapSeverity(falcopayload),
		Result:      mapResult(falcopayload),
		Description: falcopayload.Output,
		Properties:  properties,
		Subjects:    mapResource(falcopayload, namespace),
	}, namespace
}

// check for low priority events to delete first
func checklow(result []wgpolicy.PolicyReportResult) (swapint int) {
	for i, j := range result {
		if j.Severity == medium || j.Severity == low || j.Severity == info {
			return i
		}
	}
	return -1
}

// update summary for clusterpolicyreport 'report'
func updateClusterPolicyReportSummary(event *wgpolicy.PolicyReportResult) {
	if event.Result == fail {
		clusterPolicyReport.Summary.Fail++
	} else {
		clusterPolicyReport.Summary.Warn++
	}
}

// update summary for specific policyreport in 'policyReports' at index 'n'
func updatePolicyReportSummary(rep *wgpolicy.PolicyReport, event *wgpolicy.PolicyReportResult) {
	if event.Result == fail {
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
				Labels: map[string]string{
					"app.kubernetes.io/created-by": "falcosidekick",
				},
			},
			Summary: wgpolicy.PolicyReportSummary{
				Fail: 0,
				Warn: 0,
			},
		}
		if falcosidekickNamespace != "" && falcosidekickNamespaceUID != "" {
			policyReports[namespace].ObjectMeta.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Namespace",
					Name:       falcosidekickNamespace,
					UID:        falcosidekickNamespaceUID,
					Controller: new(bool),
				},
			}
		}
	}

	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	updatePolicyReportSummary(policyReports[namespace], event)
	if len(policyReports[namespace].Results) == c.Config.PolicyReport.MaxEvents {
		if c.Config.PolicyReport.PruneByPriority {
			pruningLogicForPolicyReports(namespace)
		} else {
			summaryDeletion(&policyReports[namespace].Summary, policyReports[namespace].Results[0].Result)
			policyReports[namespace].Results = policyReports[namespace].Results[1:]
		}
	}
	policyReports[namespace].Results = append(policyReports[namespace].Results, *event)
	_, getErr := policyr.Get(context.Background(), policyReports[namespace].Name, metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		result, err := policyr.Create(context.TODO(), policyReports[namespace], metav1.CreateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Can't create Policy Report %v in namespace %v\n", err, namespace)
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
		if c.Config.PolicyReport.PruneByPriority {
			pruningLogicForClusterPolicyReport()
		} else {
			summaryDeletion(&clusterPolicyReport.Summary, clusterPolicyReport.Results[0].Result)

			clusterPolicyReport.Results = clusterPolicyReport.Results[1:]
		}
	}

	clusterPolicyReport.Results = append(clusterPolicyReport.Results, *event)

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
	policyReport, ok := policyReports[namespace]
	if !ok {
		return
	}

	result := policyReport.Results[0]

	//To do for pruning for pruning one of policyreports
	checklowvalue := checklow(policyReports[namespace].Results)
	if checklowvalue > 0 {
		result = policyReport.Results[checklowvalue]
		policyReport.Results[checklowvalue] = policyReports[namespace].Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletion(&policyReports[namespace].Summary, result.Result)
	} else {
		summaryDeletion(&policyReports[namespace].Summary, result.Result)
	}
	policyReports[namespace].Results = policyReports[namespace].Results[1:]
}

func pruningLogicForClusterPolicyReport() {
	result := clusterPolicyReport.Results[0]

	//To do for pruning cluster report
	checklowvalue := checklow(clusterPolicyReport.Results)

	if checklowvalue > 0 {
		result = clusterPolicyReport.Results[checklowvalue]
		clusterPolicyReport.Results[checklowvalue] = clusterPolicyReport.Results[0]
	}
	if checklowvalue == -1 {
		summaryDeletion(&clusterPolicyReport.Summary, result.Result)
	} else {
		summaryDeletion(&clusterPolicyReport.Summary, result.Result)
	}
	clusterPolicyReport.Results = clusterPolicyReport.Results[1:]
}

func summaryDeletion(summary *wgpolicy.PolicyReportSummary, result wgpolicy.PolicyResult) {
	switch result {
	case fail:
		summary.Fail--
	case warn:
		summary.Warn--
	case skip:
		summary.Skip--
	}
}

func mapResult(event types.FalcoPayload) wgpolicy.PolicyResult {
	if event.Priority <= types.Notice {
		return skip
	} else if event.Priority == types.Warning {
		return warn
	} else {
		return fail
	}
}

func mapSeverity(event types.FalcoPayload) wgpolicy.PolicyResultSeverity {
	if event.Priority <= types.Informational {
		return info
	} else if event.Priority <= types.Notice {
		return low
	} else if event.Priority <= types.Warning {
		return medium
	} else if event.Priority <= types.Error {
		return high
	} else {
		return critical
	}
}

func mapResource(event types.FalcoPayload, ns string) []corev1.ObjectReference {
	name := determineResourceName(event.OutputFields)
	if name != "" {
		return nil
	}

	targetResource, ok := event.OutputFields[targetResource]
	if !ok {
		return []corev1.ObjectReference{
			{
				Namespace: ns,
				Name:      toString(name),
			},
		}
	}

	resource, ok := resourceMapping[toString(targetResource)]
	if !ok {
		resource.kind = toString(targetResource)
	}

	return []corev1.ObjectReference{
		{
			Namespace:  ns,
			Name:       toString(name),
			Kind:       resource.kind,
			APIVersion: resource.apiVersion,
		},
	}
}

func determineResourceName(outputFields map[string]interface{}) string {
	name, ok := outputFields[targetName]
	if ok {
		return toString(name)
	}

	return toString(outputFields[responseName])
}

func toString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}

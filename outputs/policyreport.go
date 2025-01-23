// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"log"
	"os"

	"github.com/falcosecurity/falcosidekick/outputs/otlpmetrics"
	"go.opentelemetry.io/otel/attribute"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"

	corev1 "k8s.io/api/core/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
	crd "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned"
)

type resource struct {
	apiVersion string
	kind       string
}

const (
	clusterPolicyReportName string = "falco-cluster-policy-report"
	policyReportName        string = "falco-policy-report"
	policyReportSource      string = "Falco"

	updateStr string = "Update"
	createStr string = "Create"

	highStr     wgpolicy.PolicyResultSeverity = "high"
	lowStr      wgpolicy.PolicyResultSeverity = "low"
	mediumStr   wgpolicy.PolicyResultSeverity = "medium"
	infoStr     wgpolicy.PolicyResultSeverity = "info"
	criticalStr wgpolicy.PolicyResultSeverity = "critical"

	failStr wgpolicy.PolicyResult = "fail"
	warnStr wgpolicy.PolicyResult = "warn"
	skipStr wgpolicy.PolicyResult = "skip"

	k8sPodName       string = "k8s.pod.name"
	k8sNsName        string = "k8s.ns.name"
	kaTargetNS       string = "ka.target.namespace"
	kaTargetResource string = "ka.target.resource"
	kaTargetName     string = "ka.target.name"
	kaRespName       string = "ka.resp.name"
)

var (
	defaultNamespace string = "default"

	// used resources in the k8saudit ruleset
	resourceMapping = map[string]resource{
		"pods":                {"v1", "Pod"},
		"services":            {"v1", "Service"},
		"secrets":             {"v1", "Secrets"},
		"configmaps":          {"v1", "ConfigMap"},
		"namespaces":          {"v1", "Namespace"},
		"serviceaccounts":     {"v1", "ServiceAccount"},
		"daemonsets":          {"apps/v1", "DaemonSet"},
		"deployments":         {"apps/v1", "Deployment"},
		"statefulsets":        {"apps/v1", "StatefulSet"},
		"cronjobs":            {"batch/v1", "CronJob"},
		"jobs":                {"batch/v1", "Job"},
		"clusterroles":        {"rbac.authorization.k8s.io/v1", "ClusterRole"},
		"clusterrolebindings": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},
		"roles":               {"rbac.authorization.k8s.io/v1", "Role"},
		"rolebindings":        {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	}
)

func newPolicyReport() *wgpolicy.PolicyReport {
	return &wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyReportName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "falcosidekick",
			},
		},
		Summary: wgpolicy.PolicyReportSummary{},
	}
}

func newClusterPolicyReport() *wgpolicy.ClusterPolicyReport {
	return &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterPolicyReportName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "falcosidekick",
			},
		},
		Summary: wgpolicy.PolicyReportSummary{},
	}
}

func NewPolicyReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		clientConfig, err = clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Unable to load kube config file: %v\n", err)
			return nil, err
		}
	}
	crdclient, err := crd.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	if config.PolicyReport.FalcoNamespace == "" {
		dat, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Unable to get the Falcosidekick's namespace, '%v' used instead\n", defaultNamespace)
		} else {
			defaultNamespace = string(dat)
		}
	} else {
		defaultNamespace = config.PolicyReport.FalcoNamespace
	}

	return &Client{
		OutputType:       "PolicyReport",
		Config:           config,
		Stats:            stats,
		PromStats:        promStats,
		OTLPMetrics:      otlpMetrics,
		StatsdClient:     statsdClient,
		DogstatsdClient:  dogstatsdClient,
		KubernetesClient: clientset,
		Crdclient:        crdclient,
	}, nil
}

// UpdateOrCreatePolicyReport creates/updates PolicyReport/ClusterPolicyReport Resource in Kubernetes
func (c *Client) UpdateOrCreatePolicyReport(falcopayload types.FalcoPayload) {
	c.Stats.PolicyReport.Add(Total, 1)

	result := newResult(falcopayload)
	namespace := getNamespace(falcopayload.OutputFields)

	var err error
	if namespace != "" {
		err = c.createOrUpdatePolicyReport(result, namespace)
	} else {
		err = c.createOrUpdateClusterPolicyReport(result)
	}
	if err == nil {
		go c.CountMetric(Outputs, 1, []string{"output:policyreport", "status:" + OK})
		c.Stats.PolicyReport.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "policyreport", "status": OK}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "policyreport"),
			attribute.String("status", OK)).Inc()
	} else {
		go c.CountMetric(Outputs, 1, []string{"output:policyreport", "status:" + Error})
		c.Stats.PolicyReport.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "policyreport", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "policyreport"),
			attribute.String("status", Error)).Inc()
	}
}

// newResult creates a new entry for Reports
func newResult(falcopayload types.FalcoPayload) *wgpolicy.PolicyReportResult {
	var properties = make(map[string]string)
	for i, j := range falcopayload.OutputFields {
		properties[i] = toString(j)
	}

	return &wgpolicy.PolicyReportResult{
		Policy:      falcopayload.Source,
		Rule:        falcopayload.Rule,
		Category:    "SI - System and Information Integrity",
		Source:      policyReportSource,
		Timestamp:   metav1.Timestamp{Seconds: int64(falcopayload.Time.Second()), Nanos: int32(falcopayload.Time.Nanosecond())}, //nolint:gosec // disable G115
		Severity:    mapSeverity(falcopayload),
		Result:      mapResult(falcopayload),
		Description: falcopayload.Output,
		Properties:  properties,
		Subjects:    getSubjects(falcopayload),
	}
}

func (c *Client) createOrUpdatePolicyReport(result *wgpolicy.PolicyReportResult, namespace string) error {
	action := updateStr

	_, err := c.KubernetesClient.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		if errorsv1.IsNotFound(err) {
			log.Printf("[INFO]  : PolicyReport - Can't find the namespace '%v', fallback to '%v'\n", namespace, defaultNamespace)
			namespace = defaultNamespace
			result.Subjects[0].Namespace = defaultNamespace
		}
	}

	policyr, err := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace).Get(context.Background(), policyReportName, metav1.GetOptions{})
	if err != nil {
		if !errorsv1.IsNotFound(err) {
			return err
		}
	}
	if policyr.Name == "" {
		policyr = newPolicyReport()
		action = createStr
	}

	policyr.Results = append(policyr.Results, *result)

	if len(policyr.Results) > c.Config.PolicyReport.MaxEvents {
		policyr.Results = policyr.Results[1:]
	}

	policyr.Summary = getSummary(policyr.Results)

	if action == createStr {
		_, err := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace).Create(context.Background(), policyr, metav1.CreateOptions{})
		if err != nil {
			if errorsv1.IsAlreadyExists(err) {
				action = updateStr
				policyr, err = c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace).Get(context.Background(), policyReportName, metav1.GetOptions{})
				if err != nil {
					log.Printf("[ERROR] : PolicyReport - Error with with the Policy Report %v in namespace %v: %v\n", policyReportName, namespace, err)
					return err
				}
				_, err := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace).Update(context.Background(), policyr, metav1.UpdateOptions{})
				if err != nil {
					log.Printf("[ERROR] : PolicyReport - Can't %v the Policy Report %v in namespace %v: %v\n", action, policyReportName, namespace, err)
					return err
				}
			} else {
				log.Printf("[ERROR] : PolicyReport - Can't %v the Policy Report %v in namespace %v: %v\n", action, policyReportName, namespace, err)
				return err
			}
		}
		log.Printf("[INFO]  : PolicyReport - %v the Policy Report %v in namespace %v\n", action, policyReportName, namespace)
		return nil
	} else {
		_, err := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace).Update(context.Background(), policyr, metav1.UpdateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Can't %v the Policy Report %v in namespace %v: %v\n", action, policyReportName, namespace, err)
			return err
		}
		log.Printf("[INFO]  : PolicyReport - %v the Policy Report %v in namespace %v\n", action, policyReportName, namespace)
		return nil
	}
}

func (c *Client) createOrUpdateClusterPolicyReport(result *wgpolicy.PolicyReportResult) error {
	action := updateStr

	cpolicyr, err := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports().Get(context.Background(), clusterPolicyReportName, metav1.GetOptions{})
	if err != nil {
		if !errorsv1.IsNotFound(err) {
			return err
		}
	}
	if cpolicyr.Name == "" {
		cpolicyr = newClusterPolicyReport()
		action = createStr
	}

	cpolicyr.Results = append(cpolicyr.Results, *result)

	if len(cpolicyr.Results) > c.Config.PolicyReport.MaxEvents {
		cpolicyr.Results = cpolicyr.Results[1:]
	}

	cpolicyr.Summary = getSummary(cpolicyr.Results)

	if action == createStr {
		_, err := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports().Create(context.Background(), cpolicyr, metav1.CreateOptions{})
		if err != nil {
			if errorsv1.IsAlreadyExists(err) {
				action = updateStr
				cpolicyr, err = c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports().Get(context.Background(), policyReportName, metav1.GetOptions{})
				if err != nil {
					log.Printf("[ERROR] : PolicyReport - Error with with the Cluster Policy Report %v: %v\n", policyReportName, err)
					return err
				}
				_, err := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports().Update(context.Background(), cpolicyr, metav1.UpdateOptions{})
				if err != nil {
					log.Printf("[ERROR] : PolicyReport - Can't %v the Cluster Policy Report %v: %v\n", action, policyReportName, err)
					return err
				}
			} else {
				log.Printf("[ERROR] : PolicyReport - Can't %v the Cluster Policy Report %v: %v\n", action, clusterPolicyReportName, err)
				return err
			}
		}
		log.Printf("[INFO]  : PolicyReport - %v Cluster the Policy Report %v\n", action, policyReportName)
		return nil
	} else {
		_, err := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports().Update(context.Background(), cpolicyr, metav1.UpdateOptions{})
		if err != nil {
			log.Printf("[ERROR] : PolicyReport - Can't %v the Cluster Policy Report %v: %v\n", action, clusterPolicyReportName, err)
			return err
		}
		log.Printf("[INFO]  : PolicyReport - %v the ClusterPolicy Report %v\n", action, policyReportName)
		return nil
	}
}

func getSummary(results []wgpolicy.PolicyReportResult) wgpolicy.PolicyReportSummary {
	var summary wgpolicy.PolicyReportSummary
	for _, i := range results {
		switch i.Result {
		case "pass":
			summary.Pass++
		case "fail":
			summary.Fail++
		case "warn":
			summary.Warn++
		case "error":
			summary.Error++
		case "skip":
			summary.Skip++
		}
	}
	return summary
}

func mapResult(event types.FalcoPayload) wgpolicy.PolicyResult {
	if event.Priority <= types.Notice {
		return skipStr
	} else if event.Priority == types.Warning {
		return warnStr
	} else {
		return failStr
	}
}

func mapSeverity(event types.FalcoPayload) wgpolicy.PolicyResultSeverity {
	if event.Priority <= types.Informational {
		return infoStr
	} else if event.Priority <= types.Notice {
		return lowStr
	} else if event.Priority <= types.Warning {
		return mediumStr
	} else if event.Priority <= types.Error {
		return highStr
	} else {
		return criticalStr
	}
}

func getSubjects(event types.FalcoPayload) []corev1.ObjectReference {
	name, kind := getResourceNameKind(event.OutputFields)
	if name == "" || kind == "" {
		return nil
	}
	namespace := getNamespace(event.OutputFields)

	return []corev1.ObjectReference{
		{
			Namespace:  namespace,
			Name:       toString(name),
			Kind:       resourceMapping[kind].kind,
			APIVersion: resourceMapping[kind].apiVersion,
		},
	}
}

func getNamespace(outputFields map[string]interface{}) string {
	if outputFields[k8sNsName] != nil {
		return toString(outputFields[k8sNsName])
	}
	if outputFields[kaTargetNS] != nil {
		return toString(outputFields[kaTargetNS])
	}

	return ""
}

func getResourceNameKind(outputFields map[string]interface{}) (string, string) {
	if outputFields[k8sPodName] != nil {
		return toString(outputFields[k8sPodName]), "pods"
	}
	if outputFields[kaTargetResource] == nil {
		return "", ""
	}
	if outputFields[kaTargetName] != nil {
		return toString(outputFields[kaTargetName]), toString(outputFields[kaTargetResource])
	}
	if outputFields[kaRespName] != nil {
		return toString(outputFields[kaRespName].(string)), toString(outputFields[kaTargetResource])
	}

	return "", ""
}

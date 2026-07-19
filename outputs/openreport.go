// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned"
	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

type openReportResource struct {
	apiVersion string
	kind       string
}

const (
	openReportName        = "falco-report"
	openClusterReportName = "falco-cluster-report"
	openReportSource      = "Falco"
	openReportDefaultNS   = "default"

	openReportUpdate = "Update"
	openReportCreate = "Create"

	openReportHigh     openreports.ResultSeverity = "high"
	openReportLow      openreports.ResultSeverity = "low"
	openReportMedium   openreports.ResultSeverity = "medium"
	openReportInfo     openreports.ResultSeverity = "info"
	openReportCritical openreports.ResultSeverity = "critical"

	openReportPass  openreports.Result = "pass"
	openReportFail  openreports.Result = "fail"
	openReportWarn  openreports.Result = "warn"
	openReportError openreports.Result = "error"
	openReportSkip  openreports.Result = "skip"

	openReportK8sPodName      = "k8s.pod.name"
	openReportK8sNamespace    = "k8s.ns.name"
	openReportTargetNamespace = "ka.target.namespace"
	openReportTargetResource  = "ka.target.resource"
	openReportTargetName      = "ka.target.name"
	openReportResponseName    = "ka.resp.name"
)

var openReportResourceMapping = map[string]openReportResource{
	"pods":                {"v1", "Pod"},
	"services":            {"v1", "Service"},
	"secrets":             {"v1", "Secret"},
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

func newOpenReport(namespace string) *openreports.Report {
	return &openreports.Report{
		TypeMeta: metav1.TypeMeta{
			APIVersion: openreports.SchemeGroupVersion.String(),
			Kind:       "Report",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      openReportName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "falcosidekick",
			},
		},
		Summary: openreports.ReportSummary{},
	}
}

func newOpenClusterReport() *openreports.ClusterReport {
	return &openreports.ClusterReport{
		TypeMeta: metav1.TypeMeta{
			APIVersion: openreports.SchemeGroupVersion.String(),
			Kind:       "ClusterReport",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: openClusterReportName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "falcosidekick",
			},
		},
		Summary: openreports.ReportSummary{},
	}
}

// NewOpenReportClient creates a client for OpenReports Report and ClusterReport resources.
func NewOpenReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	if config.OpenReport.MaxEvents <= 0 {
		err := fmt.Errorf("openreport maxevents must be greater than zero")
		utils.Log(utils.ErrorLvl, "OpenReport", err.Error())
		return nil, err
	}

	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		clientConfig, err = clientcmd.BuildConfigFromFlags("", config.OpenReport.Kubeconfig)
		if err != nil {
			utils.Log(utils.ErrorLvl, "OpenReport", fmt.Sprintf("Unable to load kube config file: %v", err))
			return nil, err
		}
	}

	reportsClient, err := openreportsclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	kubernetesClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	fallbackNamespace := openReportDefaultNS
	if config.OpenReport.FalcoNamespace != "" {
		fallbackNamespace = config.OpenReport.FalcoNamespace
	} else {
		namespace, readErr := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if readErr != nil {
			utils.Log(utils.ErrorLvl, "OpenReport", fmt.Sprintf("Unable to get the Falcosidekick namespace, '%v' used instead", fallbackNamespace))
		} else if value := strings.TrimSpace(string(namespace)); value != "" {
			fallbackNamespace = value
		}
	}

	return &Client{
		OutputType:                 "OpenReport",
		Config:                     config,
		Stats:                      stats,
		PromStats:                  promStats,
		OTLPMetrics:                otlpMetrics,
		StatsdClient:               statsdClient,
		DogstatsdClient:            dogstatsdClient,
		KubernetesClient:           kubernetesClient,
		OpenReportsClient:          reportsClient,
		openReportDefaultNamespace: fallbackNamespace,
	}, nil
}

// UpdateOrCreateOpenReport creates or updates an OpenReports Report or ClusterReport.
func (c *Client) UpdateOrCreateOpenReport(falcopayload types.FalcoPayload) {
	c.Stats.OpenReport.Add(Total, 1)

	result := newOpenReportResult(falcopayload)
	namespace := getOpenReportNamespace(falcopayload.OutputFields)

	var err error
	if namespace != "" {
		err = c.createOrUpdateOpenReport(result, namespace)
	} else {
		err = c.createOrUpdateOpenClusterReport(result)
	}

	status := OK
	if err != nil {
		status = Error
	}
	c.recordOpenReportMetric(status)
}

func (c *Client) recordOpenReportMetric(status string) {
	go c.CountMetric(Outputs, 1, []string{"output:openreport", "status:" + status})
	c.Stats.OpenReport.Add(status, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openreport", "status": status}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "openreport"), attribute.String("status", status)).Inc()
}

func newOpenReportResult(falcopayload types.FalcoPayload) *openreports.ReportResult {
	properties := make(map[string]string, len(falcopayload.OutputFields))
	for key, value := range falcopayload.OutputFields {
		properties[key] = toString(value)
	}

	return &openreports.ReportResult{
		Policy:      falcopayload.Source,
		Rule:        falcopayload.Rule,
		Category:    "SI - System and Information Integrity",
		Source:      openReportSource,
		Timestamp:   metav1.Timestamp{Seconds: falcopayload.Time.Unix(), Nanos: int32(falcopayload.Time.Nanosecond())}, //nolint:gosec // nanoseconds always fit in int32
		Severity:    mapOpenReportSeverity(falcopayload),
		Result:      mapOpenReportResult(falcopayload),
		Description: falcopayload.Output,
		Properties:  properties,
		Subjects:    getOpenReportSubjects(falcopayload),
	}
}

func (c *Client) createOrUpdateOpenReport(result *openreports.ReportResult, namespace string) error {
	_, namespaceErr := c.KubernetesClient.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(namespaceErr) {
		fallbackNamespace := c.openReportDefaultNamespace
		if fallbackNamespace == "" {
			fallbackNamespace = openReportDefaultNS
		}
		utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("Can't find the namespace '%v', fallback to '%v'", namespace, fallbackNamespace))
		namespace = fallbackNamespace
		for index := range result.Subjects {
			result.Subjects[index].Namespace = fallbackNamespace
		}
	} else if namespaceErr != nil {
		// Namespace reads are optional: Report writes may be authorized without cluster-wide namespace access.
		utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("Unable to check namespace '%v', proceeding with it: %v", namespace, namespaceErr))
	}

	action := openReportUpdate
	err := retry.OnError(retry.DefaultRetry, isRetriableOpenReportError, func() error {
		reports := c.OpenReportsClient.OpenreportsV1alpha1().Reports(namespace)
		report, getErr := reports.Get(context.Background(), openReportName, metav1.GetOptions{})
		if getErr != nil && !apierrors.IsNotFound(getErr) {
			return getErr
		}

		action = openReportUpdate
		if apierrors.IsNotFound(getErr) {
			report = newOpenReport(namespace)
			action = openReportCreate
		}

		report.Results = retainOpenReportResults(append(report.Results, *result), c.Config.OpenReport.MaxEvents)
		report.Summary = getOpenReportSummary(report.Results)

		if action == openReportCreate {
			_, createErr := reports.Create(context.Background(), report, metav1.CreateOptions{})
			return createErr
		}
		_, updateErr := reports.Update(context.Background(), report, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Can't %v the Report %v in namespace %v: %v", action, openReportName, namespace, err))
		return err
	}

	utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("%v the Report %v in namespace %v", action, openReportName, namespace))
	return nil
}

func (c *Client) createOrUpdateOpenClusterReport(result *openreports.ReportResult) error {
	action := openReportUpdate
	err := retry.OnError(retry.DefaultRetry, isRetriableOpenReportError, func() error {
		reports := c.OpenReportsClient.OpenreportsV1alpha1().ClusterReports()
		report, getErr := reports.Get(context.Background(), openClusterReportName, metav1.GetOptions{})
		if getErr != nil && !apierrors.IsNotFound(getErr) {
			return getErr
		}

		action = openReportUpdate
		if apierrors.IsNotFound(getErr) {
			report = newOpenClusterReport()
			action = openReportCreate
		}

		report.Results = retainOpenReportResults(append(report.Results, *result), c.Config.OpenReport.MaxEvents)
		report.Summary = getOpenReportSummary(report.Results)

		if action == openReportCreate {
			_, createErr := reports.Create(context.Background(), report, metav1.CreateOptions{})
			return createErr
		}
		_, updateErr := reports.Update(context.Background(), report, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Can't %v the ClusterReport %v: %v", action, openClusterReportName, err))
		return err
	}

	utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("%v the ClusterReport %v", action, openClusterReportName))
	return nil
}

func isRetriableOpenReportError(err error) bool {
	return apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err)
}

func retainOpenReportResults(results []openreports.ReportResult, maxEvents int) []openreports.ReportResult {
	if maxEvents <= 0 {
		return nil
	}
	if len(results) <= maxEvents {
		return results
	}
	return results[len(results)-maxEvents:]
}

func getOpenReportSummary(results []openreports.ReportResult) openreports.ReportSummary {
	var summary openreports.ReportSummary
	for _, result := range results {
		switch result.Result {
		case openReportPass:
			summary.Pass++
		case openReportFail:
			summary.Fail++
		case openReportWarn:
			summary.Warn++
		case openReportError:
			summary.Error++
		case openReportSkip:
			summary.Skip++
		}
	}
	return summary
}

func mapOpenReportResult(event types.FalcoPayload) openreports.Result {
	if event.Priority <= types.Notice {
		return openReportSkip
	}
	if event.Priority == types.Warning {
		return openReportWarn
	}
	return openReportFail
}

func mapOpenReportSeverity(event types.FalcoPayload) openreports.ResultSeverity {
	if event.Priority <= types.Informational {
		return openReportInfo
	}
	if event.Priority <= types.Notice {
		return openReportLow
	}
	if event.Priority <= types.Warning {
		return openReportMedium
	}
	if event.Priority <= types.Error {
		return openReportHigh
	}
	return openReportCritical
}

func getOpenReportSubjects(event types.FalcoPayload) []corev1.ObjectReference {
	name, resourceName := getOpenReportResourceName(event.OutputFields)
	resource, ok := openReportResourceMapping[resourceName]
	if name == "" || !ok {
		return nil
	}

	return []corev1.ObjectReference{{
		Namespace:  getOpenReportNamespace(event.OutputFields),
		Name:       name,
		Kind:       resource.kind,
		APIVersion: resource.apiVersion,
	}}
}

func getOpenReportNamespace(outputFields map[string]interface{}) string {
	if value := outputFields[openReportK8sNamespace]; value != nil {
		return toString(value)
	}
	if value := outputFields[openReportTargetNamespace]; value != nil {
		return toString(value)
	}
	return ""
}

func getOpenReportResourceName(outputFields map[string]interface{}) (string, string) {
	if value := outputFields[openReportK8sPodName]; value != nil {
		return toString(value), "pods"
	}

	resourceValue := outputFields[openReportTargetResource]
	if resourceValue == nil {
		return "", ""
	}
	resourceName := toString(resourceValue)
	if _, ok := openReportResourceMapping[resourceName]; !ok {
		return "", ""
	}

	if value := outputFields[openReportTargetName]; value != nil {
		return toString(value), resourceName
	}
	if value := outputFields[openReportResponseName]; value != nil {
		return toString(value), resourceName
	}
	return "", ""
}

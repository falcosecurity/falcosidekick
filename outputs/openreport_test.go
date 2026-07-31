// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	stderrors "errors"
	"expvar"
	"strconv"
	"sync"
	"testing"
	"time"

	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	openreportsfake "github.com/openreports/reports-api/pkg/client/clientset/versioned/fake"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/retry"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	openReportTestNamespace = "falco"
	openReportFallbackNS    = "fallback"
)

var (
	openReportGVR        = openreports.SchemeGroupVersion.WithResource("reports")
	openClusterReportGVR = openreports.SchemeGroupVersion.WithResource("clusterreports")
)

type openReportCounterState struct {
	mu     sync.Mutex
	values map[string]int
}

type openReportRecordingCounter struct {
	state      *openReportCounterState
	attributes []attribute.KeyValue
}

func newOpenReportRecordingCounter() *openReportRecordingCounter {
	return &openReportRecordingCounter{state: &openReportCounterState{values: make(map[string]int)}}
}

func (c *openReportRecordingCounter) With(attributes ...attribute.KeyValue) otlpmetrics.Counter {
	return &openReportRecordingCounter{
		state:      c.state,
		attributes: append([]attribute.KeyValue(nil), attributes...),
	}
}

func (c *openReportRecordingCounter) Inc() {
	destination, status := "", ""
	for _, item := range c.attributes {
		switch string(item.Key) {
		case "destination":
			destination = item.Value.AsString()
		case "status":
			status = item.Value.AsString()
		}
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.values[destination+":"+status]++
}

func (c *openReportRecordingCounter) value(destination, status string) int {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return c.state.values[destination+":"+status]
}

// openReportFakeClient replaces reports-api v0.2.1's field-managed tracker
// with a basic tracker. The field-managed tracker cannot convert these objects
// when Falcosidekick resolves client-go v0.36.1 instead of reports-api's v0.34.
type openReportFakeClient struct {
	*openreportsfake.Clientset
	tracker k8stesting.ObjectTracker
}

func (c *openReportFakeClient) Tracker() k8stesting.ObjectTracker {
	return c.tracker
}

func newOpenReportTestClient(maxEvents int, objects ...runtime.Object) (*Client, *openReportFakeClient, *kubernetesfake.Clientset) {
	scheme := runtime.NewScheme()
	if err := openreports.AddToScheme(scheme); err != nil {
		panic(err)
	}
	tracker := k8stesting.NewObjectTracker(scheme, serializer.NewCodecFactory(scheme).UniversalDecoder())
	for _, object := range objects {
		if err := tracker.Add(object); err != nil {
			panic(err)
		}
	}
	generatedClient := openreportsfake.NewClientset()
	generatedClient.PrependReactor("*", "*", k8stesting.ObjectReaction(tracker))
	reportsClient := &openReportFakeClient{Clientset: generatedClient, tracker: tracker}

	statistics := new(expvar.Map)
	statistics.Init()
	statistics.Add(Total, 0)
	statistics.Add(OK, 0)
	statistics.Add(Error, 0)
	config := &types.Configuration{}
	config.OpenReport.MaxEvents = maxEvents
	coreClient := kubernetesfake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: openReportTestNamespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: openReportFallbackNS}},
	)

	return &Client{
		OutputType: "OpenReport",
		Config:     config,
		Stats: &types.Statistics{
			OpenReport: statistics,
		},
		PromStats: &types.PromStatistics{
			Outputs: prometheus.NewCounterVec(
				prometheus.CounterOpts{Name: "openreport_test_outputs", Help: "OpenReport test output count."},
				[]string{"destination", "status"},
			),
		},
		OTLPMetrics:                &otlpmetrics.OTLPMetrics{Outputs: newOpenReportRecordingCounter()},
		KubernetesClient:           coreClient,
		OpenReportsClient:          reportsClient,
		openReportDefaultNamespace: openReportFallbackNS,
	}, reportsClient, coreClient
}

func testOpenReportResult(rule string, result openreports.Result) *openreports.ReportResult {
	return &openreports.ReportResult{
		Policy:   "syscall",
		Rule:     rule,
		Source:   openReportSource,
		Severity: openReportHigh,
		Result:   result,
	}
}

func openReportRules(results []openreports.ReportResult) []string {
	rules := make([]string, 0, len(results))
	for _, result := range results {
		rules = append(rules, result.Rule)
	}
	return rules
}

func countOpenReportRule(results []openreports.ReportResult, rule string) int {
	count := 0
	for _, result := range results {
		if result.Rule == rule {
			count++
		}
	}
	return count
}

func requireOpenReportGVK(t *testing.T, object runtime.Object, kind string) {
	t.Helper()
	require.Equal(t, "openreports.io/v1alpha1", object.GetObjectKind().GroupVersionKind().GroupVersion().String())
	require.Equal(t, kind, object.GetObjectKind().GroupVersionKind().Kind)
}

func TestCreateOrUpdateOpenReport(t *testing.T) {
	client, reportsClient, _ := newOpenReportTestClient(10)

	require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("first", openReportFail), openReportTestNamespace))
	report, err := reportsClient.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(
		context.Background(), openReportName, metav1.GetOptions{},
	)
	require.NoError(t, err)
	require.Equal(t, "falco-report", report.Name)
	require.Equal(t, openReportTestNamespace, report.Namespace)
	require.Equal(t, "falcosidekick", report.Labels["app.kubernetes.io/managed-by"])
	requireOpenReportGVK(t, report, "Report")
	require.Equal(t, []string{"first"}, openReportRules(report.Results))
	require.Equal(t, openreports.ReportSummary{Fail: 1}, report.Summary)

	require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("second", openReportWarn), openReportTestNamespace))
	report, err = reportsClient.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(
		context.Background(), openReportName, metav1.GetOptions{},
	)
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, openReportRules(report.Results))
	require.Equal(t, openreports.ReportSummary{Fail: 1, Warn: 1}, report.Summary)

	var verbs []string
	for _, action := range reportsClient.Actions() {
		if action.GetResource() == openReportGVR {
			verbs = append(verbs, action.GetVerb())
			require.Equal(t, openReportTestNamespace, action.GetNamespace())
		}
	}
	require.Equal(t, []string{"get", "create", "get", "get", "update", "get"}, verbs)
}

func TestCreateOrUpdateOpenClusterReport(t *testing.T) {
	client, reportsClient, _ := newOpenReportTestClient(10)

	require.NoError(t, client.createOrUpdateOpenClusterReport(testOpenReportResult("first", openReportFail)))
	report, err := reportsClient.OpenreportsV1alpha1().ClusterReports().Get(
		context.Background(), openClusterReportName, metav1.GetOptions{},
	)
	require.NoError(t, err)
	require.Equal(t, "falco-cluster-report", report.Name)
	require.Empty(t, report.Namespace)
	require.Equal(t, "falcosidekick", report.Labels["app.kubernetes.io/managed-by"])
	requireOpenReportGVK(t, report, "ClusterReport")
	require.Equal(t, []string{"first"}, openReportRules(report.Results))

	require.NoError(t, client.createOrUpdateOpenClusterReport(testOpenReportResult("second", openReportSkip)))
	report, err = reportsClient.OpenreportsV1alpha1().ClusterReports().Get(
		context.Background(), openClusterReportName, metav1.GetOptions{},
	)
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, openReportRules(report.Results))
	require.Equal(t, openreports.ReportSummary{Fail: 1, Skip: 1}, report.Summary)

	for _, action := range reportsClient.Actions() {
		if action.GetResource() == openClusterReportGVR {
			require.Empty(t, action.GetNamespace())
		}
	}
}

func TestOpenReportRetriesAlreadyExists(t *testing.T) {
	t.Run("Report", func(t *testing.T) {
		client, reportsClient, _ := newOpenReportTestClient(10)
		createCalls := 0
		reportsClient.PrependReactor("create", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createCalls++
			if createCalls != 1 {
				return false, nil, nil
			}
			competitor := newOpenReport(openReportTestNamespace)
			competitor.Results = []openreports.ReportResult{*testOpenReportResult("competitor", openReportWarn)}
			competitor.Summary = openreports.ReportSummary{Warn: 1}
			require.NoError(t, reportsClient.Tracker().Create(openReportGVR, competitor, openReportTestNamespace))
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "openreports.io", Resource: "reports"}, openReportName)
		})

		require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), openReportTestNamespace))
		report, err := reportsClient.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(context.Background(), openReportName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, []string{"competitor", "incoming"}, openReportRules(report.Results))
		require.Equal(t, 1, countOpenReportRule(report.Results, "incoming"))
	})

	t.Run("ClusterReport", func(t *testing.T) {
		client, reportsClient, _ := newOpenReportTestClient(10)
		createCalls := 0
		reportsClient.PrependReactor("create", "clusterreports", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createCalls++
			if createCalls != 1 {
				return false, nil, nil
			}
			competitor := newOpenClusterReport()
			competitor.Results = []openreports.ReportResult{*testOpenReportResult("competitor", openReportWarn)}
			competitor.Summary = openreports.ReportSummary{Warn: 1}
			require.NoError(t, reportsClient.Tracker().Create(openClusterReportGVR, competitor, ""))
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "openreports.io", Resource: "clusterreports"}, openClusterReportName)
		})

		require.NoError(t, client.createOrUpdateOpenClusterReport(testOpenReportResult("incoming", openReportFail)))
		report, err := reportsClient.OpenreportsV1alpha1().ClusterReports().Get(context.Background(), openClusterReportName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, []string{"competitor", "incoming"}, openReportRules(report.Results))
		require.Equal(t, 1, countOpenReportRule(report.Results, "incoming"))
	})
}

func TestOpenReportRetriesConflictWithFreshState(t *testing.T) {
	tests := []struct {
		name       string
		resource   string
		seed       runtime.Object
		updateGVR  schema.GroupVersionResource
		invoke     func(*Client) error
		getResults func(*openReportFakeClient) ([]openreports.ReportResult, error)
	}{
		{
			name:      "Report",
			resource:  "reports",
			seed:      newOpenReport(openReportTestNamespace),
			updateGVR: openReportGVR,
			invoke: func(client *Client) error {
				return client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), openReportTestNamespace)
			},
			getResults: func(client *openReportFakeClient) ([]openreports.ReportResult, error) {
				report, err := client.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(context.Background(), openReportName, metav1.GetOptions{})
				return report.Results, err
			},
		},
		{
			name:      "ClusterReport",
			resource:  "clusterreports",
			seed:      newOpenClusterReport(),
			updateGVR: openClusterReportGVR,
			invoke: func(client *Client) error {
				return client.createOrUpdateOpenClusterReport(testOpenReportResult("incoming", openReportFail))
			},
			getResults: func(client *openReportFakeClient) ([]openreports.ReportResult, error) {
				report, err := client.OpenreportsV1alpha1().ClusterReports().Get(context.Background(), openClusterReportName, metav1.GetOptions{})
				return report.Results, err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accessor, err := meta.Accessor(test.seed)
			require.NoError(t, err)
			accessor.SetResourceVersion("1")
			switch report := test.seed.(type) {
			case *openreports.Report:
				report.Results = []openreports.ReportResult{*testOpenReportResult("existing", openReportSkip)}
			case *openreports.ClusterReport:
				report.Results = []openreports.ReportResult{*testOpenReportResult("existing", openReportSkip)}
			}

			client, reportsClient, _ := newOpenReportTestClient(10, test.seed)
			updateCalls := 0
			reportsClient.PrependReactor("update", test.resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateCalls++
				if updateCalls != 1 {
					return false, nil, nil
				}
				var competitor runtime.Object
				switch report := test.seed.(type) {
				case *openreports.Report:
					copy := report.DeepCopy()
					copy.Results = append(copy.Results, *testOpenReportResult("competitor", openReportWarn))
					copy.ResourceVersion = "2"
					competitor = copy
				case *openreports.ClusterReport:
					copy := report.DeepCopy()
					copy.Results = append(copy.Results, *testOpenReportResult("competitor", openReportWarn))
					copy.ResourceVersion = "2"
					competitor = copy
				}
				require.NoError(t, reportsClient.Tracker().Update(test.updateGVR, competitor, action.GetNamespace()))
				return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "openreports.io", Resource: test.resource}, accessor.GetName(), stderrors.New("conflict"))
			})

			require.NoError(t, test.invoke(client))
			results, err := test.getResults(reportsClient)
			require.NoError(t, err)
			require.Equal(t, []string{"existing", "competitor", "incoming"}, openReportRules(results))
			require.Equal(t, 1, countOpenReportRule(results, "incoming"))
			require.Equal(t, 2, updateCalls)
		})
	}
}

func TestOpenReportRetryBoundsAndNonRetriableErrors(t *testing.T) {
	existing := newOpenReport(openReportTestNamespace)
	existing.ResourceVersion = "1"
	client, reportsClient, _ := newOpenReportTestClient(10, existing)
	updateCalls := 0
	reportsClient.PrependReactor("update", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "openreports.io", Resource: "reports"}, openReportName, stderrors.New("conflict"))
	})
	require.Error(t, client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), openReportTestNamespace))
	require.Equal(t, retry.DefaultRetry.Steps, updateCalls)

	client, reportsClient, _ = newOpenReportTestClient(10)
	getCalls := 0
	reportsClient.PrependReactor("get", "clusterreports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getCalls++
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "openreports.io", Resource: "clusterreports"}, openClusterReportName, stderrors.New("forbidden"))
	})
	require.Error(t, client.createOrUpdateOpenClusterReport(testOpenReportResult("incoming", openReportFail)))
	require.Equal(t, 1, getCalls)
}

func TestOpenReportFIFOAndSummary(t *testing.T) {
	seedReport := newOpenReport(openReportTestNamespace)
	seedReport.Results = []openreports.ReportResult{
		*testOpenReportResult("oldest", openReportFail),
		*testOpenReportResult("middle", openReportSkip),
		*testOpenReportResult("newest", openReportWarn),
	}
	seedReport.Summary = openreports.ReportSummary{Fail: 99}
	seedReport.ResourceVersion = "1"
	client, reportsClient, _ := newOpenReportTestClient(2, seedReport)
	require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), openReportTestNamespace))
	report, err := reportsClient.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(context.Background(), openReportName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"newest", "incoming"}, openReportRules(report.Results))
	require.Equal(t, openreports.ReportSummary{Fail: 1, Warn: 1}, report.Summary)

	seedClusterReport := newOpenClusterReport()
	seedClusterReport.Results = []openreports.ReportResult{
		*testOpenReportResult("oldest", openReportFail),
		*testOpenReportResult("middle", openReportSkip),
		*testOpenReportResult("newest", openReportWarn),
	}
	seedClusterReport.ResourceVersion = "1"
	client, reportsClient, _ = newOpenReportTestClient(2, seedClusterReport)
	require.NoError(t, client.createOrUpdateOpenClusterReport(testOpenReportResult("incoming", openReportSkip)))
	clusterReport, err := reportsClient.OpenreportsV1alpha1().ClusterReports().Get(context.Background(), openClusterReportName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"newest", "incoming"}, openReportRules(clusterReport.Results))
	require.Equal(t, openreports.ReportSummary{Warn: 1, Skip: 1}, clusterReport.Summary)
}

func TestOpenReportSummaryCountsEveryResult(t *testing.T) {
	results := []openreports.ReportResult{
		*testOpenReportResult("pass-one", openReportPass),
		*testOpenReportResult("pass-two", openReportPass),
		*testOpenReportResult("fail", openReportFail),
		*testOpenReportResult("warn", openReportWarn),
		*testOpenReportResult("error", openReportError),
		*testOpenReportResult("skip", openReportSkip),
	}

	require.Equal(t, openreports.ReportSummary{Pass: 2, Fail: 1, Warn: 1, Error: 1, Skip: 1}, getOpenReportSummary(results))
}

func TestOpenReportResultMapping(t *testing.T) {
	timestamp := time.Date(2026, time.July, 19, 17, 42, 31, 123456789, time.UTC)
	payload := types.FalcoPayload{
		Output:   "Falco alert",
		Priority: types.Error,
		Rule:     "Unexpected process",
		Time:     timestamp,
		Source:   "syscall",
		OutputFields: map[string]interface{}{
			openReportK8sPodName:   "falco-0",
			openReportK8sNamespace: "falco",
			"proc.pid":             float64(42),
		},
	}
	result := newOpenReportResult(payload)
	require.Equal(t, "syscall", result.Policy)
	require.Equal(t, payload.Rule, result.Rule)
	require.Equal(t, openReportSource, result.Source)
	require.Equal(t, payload.Output, result.Description)
	require.Equal(t, timestamp.Unix(), result.Timestamp.Seconds)
	require.Equal(t, int32(timestamp.Nanosecond()), result.Timestamp.Nanos)
	require.Equal(t, "42", result.Properties["proc.pid"])
	require.Equal(t, openReportHigh, result.Severity)
	require.Equal(t, openReportFail, result.Result)
	require.Equal(t, []corev1.ObjectReference{{Namespace: "falco", Name: "falco-0", Kind: "Pod", APIVersion: "v1"}}, result.Subjects)

	tests := []struct {
		priority types.PriorityType
		severity openreports.ResultSeverity
		result   openreports.Result
	}{
		{types.Debug, openReportInfo, openReportSkip},
		{types.Informational, openReportInfo, openReportSkip},
		{types.Notice, openReportLow, openReportSkip},
		{types.Warning, openReportMedium, openReportWarn},
		{types.Error, openReportHigh, openReportFail},
		{types.Critical, openReportCritical, openReportFail},
		{types.Alert, openReportCritical, openReportFail},
		{types.Emergency, openReportCritical, openReportFail},
	}
	for _, test := range tests {
		payload.Priority = test.priority
		require.Equal(t, test.severity, mapOpenReportSeverity(payload), test.priority.String())
		require.Equal(t, test.result, mapOpenReportResult(payload), test.priority.String())
	}
}

func TestOpenReportSubjectMappingIsSafe(t *testing.T) {
	base := types.FalcoPayload{OutputFields: map[string]interface{}{}}
	require.Nil(t, getOpenReportSubjects(base))

	base.OutputFields = map[string]interface{}{
		openReportTargetResource:  "secrets",
		openReportResponseName:    float64(123),
		openReportTargetNamespace: "falco",
	}
	require.Equal(t, []corev1.ObjectReference{{Namespace: "falco", Name: "123", Kind: "Secret", APIVersion: "v1"}}, getOpenReportSubjects(base))

	base.OutputFields = map[string]interface{}{
		openReportTargetResource: "unknownwidgets",
		openReportTargetName:     "widget",
	}
	require.Nil(t, getOpenReportSubjects(base))
}

func TestOpenReportNamespaceFallback(t *testing.T) {
	t.Run("rewrites existing subjects", func(t *testing.T) {
		client, reportsClient, _ := newOpenReportTestClient(10)
		result := testOpenReportResult("incoming", openReportFail)
		result.Subjects = []corev1.ObjectReference{{Namespace: "missing", Name: "pod", Kind: "Pod", APIVersion: "v1"}}
		require.NoError(t, client.createOrUpdateOpenReport(result, "missing"))
		report, err := reportsClient.OpenreportsV1alpha1().Reports(openReportFallbackNS).Get(context.Background(), openReportName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, openReportFallbackNS, report.Results[0].Subjects[0].Namespace)
	})

	t.Run("allows a subjectless result", func(t *testing.T) {
		client, reportsClient, _ := newOpenReportTestClient(10)
		require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), "missing"))
		report, err := reportsClient.OpenreportsV1alpha1().Reports(openReportFallbackNS).Get(context.Background(), openReportName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Nil(t, report.Results[0].Subjects)
	})

	t.Run("namespace authorization is optional", func(t *testing.T) {
		client, reportsClient, coreClient := newOpenReportTestClient(10)
		coreClient.PrependReactor("get", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, openReportTestNamespace, stderrors.New("forbidden"))
		})
		require.NoError(t, client.createOrUpdateOpenReport(testOpenReportResult("incoming", openReportFail), openReportTestNamespace))
		_, err := reportsClient.OpenreportsV1alpha1().Reports(openReportTestNamespace).Get(context.Background(), openReportName, metav1.GetOptions{})
		require.NoError(t, err)
	})
}

func TestOpenReportFallbackIsPerClient(t *testing.T) {
	previousLegacyNamespace := defaultNamespace
	defaultNamespace = "legacy-shared"
	t.Cleanup(func() { defaultNamespace = previousLegacyNamespace })

	firstClient, firstReportsClient, _ := newOpenReportTestClient(10)
	firstClient.openReportDefaultNamespace = "fallback-one"
	secondClient, secondReportsClient, _ := newOpenReportTestClient(10)
	secondClient.openReportDefaultNamespace = "fallback-two"

	require.NoError(t, firstClient.createOrUpdateOpenReport(testOpenReportResult("first", openReportFail), "missing"))
	require.NoError(t, secondClient.createOrUpdateOpenReport(testOpenReportResult("second", openReportFail), "missing"))

	firstReport, err := firstReportsClient.OpenreportsV1alpha1().Reports("fallback-one").Get(context.Background(), "falco-report", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"first"}, openReportRules(firstReport.Results))

	secondReport, err := secondReportsClient.OpenreportsV1alpha1().Reports("fallback-two").Get(context.Background(), "falco-report", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"second"}, openReportRules(secondReport.Results))
}

func TestNewOpenReportClientRejectsInvalidMaxEvents(t *testing.T) {
	for _, maxEvents := range []int{0, -1} {
		config := &types.Configuration{}
		config.OpenReport.MaxEvents = maxEvents
		client, err := NewOpenReportClient(config, nil, nil, nil, nil, nil)
		require.Error(t, err)
		require.Nil(t, client)
	}
}

func TestUpdateOrCreateOpenReportMetrics(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client, _, _ := newOpenReportTestClient(10)
		counter := client.OTLPMetrics.Outputs.(*openReportRecordingCounter)
		payload := types.FalcoPayload{
			Priority: types.Error,
			Rule:     "rule",
			Time:     time.Now(),
			Source:   "syscall",
			OutputFields: map[string]interface{}{
				openReportK8sNamespace: openReportTestNamespace,
			},
		}
		client.UpdateOrCreateOpenReport(payload)
		require.Equal(t, "1", client.Stats.OpenReport.Get(Total).String())
		require.Equal(t, "1", client.Stats.OpenReport.Get(OK).String())
		require.Equal(t, "0", client.Stats.OpenReport.Get(Error).String())
		require.Equal(t, float64(1), testutil.ToFloat64(client.PromStats.Outputs.WithLabelValues("openreport", OK)))
		require.Equal(t, 1, counter.value("openreport", OK))
	})

	t.Run("error", func(t *testing.T) {
		client, reportsClient, _ := newOpenReportTestClient(10)
		counter := client.OTLPMetrics.Outputs.(*openReportRecordingCounter)
		reportsClient.PrependReactor("get", "clusterreports", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "openreports.io", Resource: "clusterreports"}, openClusterReportName, stderrors.New("forbidden"))
		})
		client.UpdateOrCreateOpenReport(types.FalcoPayload{Priority: types.Error, Rule: "rule", Time: time.Now(), Source: "syscall"})
		require.Equal(t, "1", client.Stats.OpenReport.Get(Total).String())
		require.Equal(t, "0", client.Stats.OpenReport.Get(OK).String())
		require.Equal(t, "1", client.Stats.OpenReport.Get(Error).String())
		require.Equal(t, float64(1), testutil.ToFloat64(client.PromStats.Outputs.WithLabelValues("openreport", Error)))
		require.Equal(t, 1, counter.value("openreport", Error))
	})
}

func TestOpenReportConcurrentUpdatesDoNotLoseResults(t *testing.T) {
	tests := []struct {
		name       string
		resource   string
		gvr        schema.GroupVersionResource
		namespace  string
		objectName string
		lock       func(*Client) *sync.Mutex
		invoke     func(*Client, *openreports.ReportResult) error
		results    func(runtime.Object) ([]openreports.ReportResult, openreports.ReportSummary)
	}{
		{
			name:       "Report",
			resource:   "reports",
			gvr:        openReportGVR,
			namespace:  openReportTestNamespace,
			objectName: openReportName,
			lock:       func(client *Client) *sync.Mutex { return &client.openReportMutex },
			invoke: func(client *Client, result *openreports.ReportResult) error {
				return client.createOrUpdateOpenReport(result, openReportTestNamespace)
			},
			results: func(object runtime.Object) ([]openreports.ReportResult, openreports.ReportSummary) {
				report := object.(*openreports.Report)
				return report.Results, report.Summary
			},
		},
		{
			name:       "ClusterReport",
			resource:   "clusterreports",
			gvr:        openClusterReportGVR,
			objectName: openClusterReportName,
			lock:       func(client *Client) *sync.Mutex { return &client.openClusterReportMutex },
			invoke: func(client *Client, result *openreports.ReportResult) error {
				return client.createOrUpdateOpenClusterReport(result)
			},
			results: func(object runtime.Object) ([]openreports.ReportResult, openreports.ReportSummary) {
				report := object.(*openreports.ClusterReport)
				return report.Results, report.Summary
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writers := retry.DefaultRetry.Steps * 4
			client, reportsClient, _ := newOpenReportTestClient(writers + 1)
			expectedLock := test.lock(client)
			reportsClient.PrependReactor("*", test.resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				if expectedLock.TryLock() {
					expectedLock.Unlock()
					return true, nil, stderrors.New("OpenReport API transaction executed without its scope lock")
				}
				return false, nil, nil
			})

			start := make(chan struct{})
			errors := make(chan error, writers)
			var wg sync.WaitGroup
			for index := 0; index < writers; index++ {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()
					<-start
					errors <- test.invoke(client, testOpenReportResult("incoming-"+strconv.Itoa(index), openReportFail))
				}(index)
			}
			close(start)
			wg.Wait()
			close(errors)
			for err := range errors {
				require.NoError(t, err)
			}

			object, err := reportsClient.Tracker().Get(test.gvr, test.namespace, test.objectName)
			require.NoError(t, err)
			results, summary := test.results(object)
			require.Len(t, results, writers)
			for index := 0; index < writers; index++ {
				require.Equal(t, 1, countOpenReportRule(results, "incoming-"+strconv.Itoa(index)))
			}
			require.Equal(t, openreports.ReportSummary{Fail: writers}, summary)
		})
	}
}

func TestOpenReportScopesDoNotBlockEachOther(t *testing.T) {
	tests := []struct {
		name   string
		block  func(*Client) *sync.Mutex
		invoke func(*Client) error
	}{
		{
			name:  "Report lock does not block ClusterReport",
			block: func(client *Client) *sync.Mutex { return &client.openReportMutex },
			invoke: func(client *Client) error {
				return client.createOrUpdateOpenClusterReport(testOpenReportResult("cluster", openReportFail))
			},
		},
		{
			name:  "ClusterReport lock does not block Report",
			block: func(client *Client) *sync.Mutex { return &client.openClusterReportMutex },
			invoke: func(client *Client) error {
				return client.createOrUpdateOpenReport(testOpenReportResult("namespaced", openReportFail), openReportTestNamespace)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, _ := newOpenReportTestClient(10)
			blockedLock := test.block(client)
			blockedLock.Lock()
			done := make(chan error, 1)
			go func() {
				done <- test.invoke(client)
			}()

			select {
			case err := <-done:
				blockedLock.Unlock()
				require.NoError(t, err)
			case <-time.After(time.Second):
				blockedLock.Unlock()
				<-done
				require.Fail(t, "independent OpenReport scopes blocked each other")
			}
		})
	}
}

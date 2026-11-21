// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
	crd "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned"
	crdfake "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned/fake"
	crdtyped "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/generated/v1alpha2/clientset/versioned/typed/wgpolicyk8s.io/v1alpha2"

	"github.com/falcosecurity/falcosidekick/types"
)

// reportStore stands in for the API server's storage of PolicyReports and ClusterPolicyReports,
// with the optimistic concurrency the real API server enforces: an update must carry the
// resourceVersion of the stored object, or it is rejected with a Conflict. client-go's fake
// clientset does not check resourceVersion on update (the last writer silently wins), so on its
// own it can't show the bug in https://github.com/falcosecurity/falcosidekick/issues/1179.
type reportStore struct {
	mu      sync.Mutex
	objects map[string]runtime.Object // "<namespace>/<name>", cluster-scoped under "/<name>"
	version int
	// otherWriter, when set, runs just before the next update is applied, as another writer would
	// (another falcosidekick replica): it changes the stored report, so that update conflicts.
	otherWriter func(stored runtime.Object)
}

func newReportStore() *reportStore {
	return &reportStore{objects: map[string]runtime.Object{}}
}

func storeKey(namespace, name string) string { return namespace + "/" + name }

func (s *reportStore) reactor(action k8stesting.Action) (bool, runtime.Object, error) {
	gr := schema.GroupResource{Group: "wgpolicyk8s.io", Resource: action.GetResource().Resource}
	// By verb, not by type: client-go's Create and Update actions also satisfy GetAction.
	switch action.GetVerb() {
	case "get":
		a := action.(k8stesting.GetAction)
		s.mu.Lock()
		defer s.mu.Unlock()
		obj, ok := s.objects[storeKey(a.GetNamespace(), a.GetName())]
		if !ok {
			// Like the real REST client, which returns an empty object with a NotFound error
			// (falcosidekick checks its Name); the fake clientset would return nil.
			if gr.Resource == "clusterpolicyreports" {
				return true, &wgpolicy.ClusterPolicyReport{}, errorsv1.NewNotFound(gr, a.GetName())
			}
			return true, &wgpolicy.PolicyReport{}, errorsv1.NewNotFound(gr, a.GetName())
		}
		return true, obj.DeepCopyObject(), nil
	case "create":
		a := action.(k8stesting.CreateAction)
		s.mu.Lock()
		defer s.mu.Unlock()
		obj := a.GetObject().DeepCopyObject()
		m := obj.(metav1.Object)
		key := storeKey(a.GetNamespace(), m.GetName())
		if _, ok := s.objects[key]; ok {
			return true, nil, errorsv1.NewAlreadyExists(gr, m.GetName())
		}
		s.version++
		m.SetResourceVersion(strconv.Itoa(s.version))
		s.objects[key] = obj
		return true, obj.DeepCopyObject(), nil
	case "update":
		a := action.(k8stesting.UpdateAction)
		s.mu.Lock()
		defer s.mu.Unlock()
		obj := a.GetObject().DeepCopyObject()
		m := obj.(metav1.Object)
		key := storeKey(a.GetNamespace(), m.GetName())
		stored, ok := s.objects[key]
		if !ok {
			return true, nil, errorsv1.NewNotFound(gr, m.GetName())
		}
		if s.otherWriter != nil {
			s.otherWriter(stored)
			s.otherWriter = nil
			s.version++
			stored.(metav1.Object).SetResourceVersion(strconv.Itoa(s.version))
		}
		if m.GetResourceVersion() != stored.(metav1.Object).GetResourceVersion() {
			return true, nil, errorsv1.NewConflict(gr, m.GetName(),
				fmt.Errorf("the object has been modified; please apply your changes to the latest version and try again"))
		}
		s.version++
		m.SetResourceVersion(strconv.Itoa(s.version))
		s.objects[key] = obj
		return true, obj.DeepCopyObject(), nil
	}
	return false, nil, nil
}

// readLag makes every Get return only after a short pause, once it has read the report. The fake
// clientset serves one request at a time, so without it reads and writes would simply alternate;
// with it, a burst of writers all read the same version before any of them writes - what happens in
// a real cluster when a burst of Falco events arrives at once.
const readLag = 20 * time.Millisecond

type laggyCrdClient struct{ crd.Interface }

func (c laggyCrdClient) Wgpolicyk8sV1alpha2() crdtyped.Wgpolicyk8sV1alpha2Interface {
	return laggyGroup{c.Interface.Wgpolicyk8sV1alpha2()}
}

type laggyGroup struct {
	crdtyped.Wgpolicyk8sV1alpha2Interface
}

func (g laggyGroup) PolicyReports(namespace string) crdtyped.PolicyReportInterface {
	return laggyPolicyReports{g.Wgpolicyk8sV1alpha2Interface.PolicyReports(namespace)}
}

func (g laggyGroup) ClusterPolicyReports() crdtyped.ClusterPolicyReportInterface {
	return laggyClusterPolicyReports{g.Wgpolicyk8sV1alpha2Interface.ClusterPolicyReports()}
}

type laggyPolicyReports struct{ crdtyped.PolicyReportInterface }

func (r laggyPolicyReports) Get(ctx context.Context, name string, opts metav1.GetOptions) (*wgpolicy.PolicyReport, error) {
	report, err := r.PolicyReportInterface.Get(ctx, name, opts)
	time.Sleep(readLag)
	return report, err
}

type laggyClusterPolicyReports struct {
	crdtyped.ClusterPolicyReportInterface
}

func (r laggyClusterPolicyReports) Get(ctx context.Context, name string, opts metav1.GetOptions) (*wgpolicy.ClusterPolicyReport, error) {
	report, err := r.ClusterPolicyReportInterface.Get(ctx, name, opts)
	time.Sleep(readLag)
	return report, err
}

func newConcurrencyTestClient(t *testing.T, store *reportStore, namespaces ...string) *Client {
	t.Helper()
	crdclient := crdfake.NewSimpleClientset()
	for _, resource := range []string{"policyreports", "clusterpolicyreports"} {
		crdclient.PrependReactor("*", resource, store.reactor)
	}
	objects := make([]runtime.Object, 0, len(namespaces))
	for _, ns := range namespaces {
		objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	config := &types.Configuration{}
	config.PolicyReport.MaxEvents = 1000
	return &Client{
		OutputType:       "PolicyReport",
		Config:           config,
		KubernetesClient: kubefake.NewSimpleClientset(objects...),
		Crdclient:        laggyCrdClient{crdclient},
	}
}

func burstOfResults(n int, namespace string) []*wgpolicy.PolicyReportResult {
	results := make([]*wgpolicy.PolicyReportResult, n)
	for i := range results {
		results[i] = &wgpolicy.PolicyReportResult{
			Policy:   "syscall",
			Rule:     fmt.Sprintf("rule-%02d", i),
			Source:   policyReportSource,
			Result:   warnStr,
			Severity: mediumStr,
			Subjects: []corev1.ObjectReference{{Namespace: namespace, Name: "pod", Kind: "Pod"}},
		}
	}
	return results
}

// writeConcurrently runs write for every result at once, as falcosidekick does for a burst of
// events (each output call runs in its own goroutine), and returns the errors.
func writeConcurrently(results []*wgpolicy.PolicyReportResult, write func(*wgpolicy.PolicyReportResult) error) []error {
	var wg sync.WaitGroup
	errs := make([]error, len(results))
	start := make(chan struct{})
	for i, r := range results {
		wg.Add(1)
		go func(i int, r *wgpolicy.PolicyReportResult) {
			defer wg.Done()
			<-start
			errs[i] = write(r)
		}(i, r)
	}
	close(start)
	wg.Wait()
	return errs
}

func rulesOf(results []wgpolicy.PolicyReportResult) []string {
	rules := make([]string, 0, len(results))
	for _, r := range results {
		rules = append(rules, r.Rule)
	}
	return rules
}

func expectedRules(results []*wgpolicy.PolicyReportResult) []string {
	rules := make([]string, 0, len(results))
	for _, r := range results {
		rules = append(rules, r.Rule)
	}
	return rules
}

func requireNoErrors(t *testing.T, errs []error) {
	t.Helper()
	var failed []string
	for i, err := range errs {
		if err != nil {
			failed = append(failed, fmt.Sprintf("event %d: %v", i, err))
		}
	}
	require.Empty(t, failed, "%d of %d concurrent writes failed", len(failed), len(errs))
}

// A burst of events for one namespace, into an existing PolicyReport: every event must end up in
// the report, and none may fail with a Conflict.
func TestPolicyReportConcurrentUpdates(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store, "app")
	require.NoError(t, c.createOrUpdatePolicyReport(burstOfResults(1, "app")[0], "app"))

	results := burstOfResults(20, "app")
	errs := writeConcurrently(results, func(r *wgpolicy.PolicyReportResult) error {
		return c.createOrUpdatePolicyReport(r, "app")
	})

	requireNoErrors(t, errs)
	stored := store.objects[storeKey("app", policyReportName)].(*wgpolicy.PolicyReport)
	require.Len(t, stored.Results, len(results)+1)
	require.Subset(t, rulesOf(stored.Results), expectedRules(results))
}

// The same burst when the namespace has no PolicyReport yet: the writers race to create it. The
// ones that lose (AlreadyExists) must still add their own result.
func TestPolicyReportConcurrentCreate(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store, "app")

	results := burstOfResults(20, "app")
	errs := writeConcurrently(results, func(r *wgpolicy.PolicyReportResult) error {
		return c.createOrUpdatePolicyReport(r, "app")
	})

	requireNoErrors(t, errs)
	stored := store.objects[storeKey("app", policyReportName)].(*wgpolicy.PolicyReport)
	require.ElementsMatch(t, expectedRules(results), rulesOf(stored.Results))
}

// A burst of host events (no namespace) into an existing ClusterPolicyReport.
func TestClusterPolicyReportConcurrentUpdates(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store)
	require.NoError(t, c.createOrUpdateClusterPolicyReport(burstOfResults(1, "")[0]))

	results := burstOfResults(20, "")
	errs := writeConcurrently(results, c.createOrUpdateClusterPolicyReport)

	requireNoErrors(t, errs)
	stored := store.objects[storeKey("", clusterPolicyReportName)].(*wgpolicy.ClusterPolicyReport)
	require.Len(t, stored.Results, len(results)+1)
	require.Subset(t, rulesOf(stored.Results), expectedRules(results))
}

// The same burst before the ClusterPolicyReport exists.
func TestClusterPolicyReportConcurrentCreate(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store)

	results := burstOfResults(20, "")
	errs := writeConcurrently(results, c.createOrUpdateClusterPolicyReport)

	requireNoErrors(t, errs)
	stored := store.objects[storeKey("", clusterPolicyReportName)].(*wgpolicy.ClusterPolicyReport)
	require.ElementsMatch(t, expectedRules(results), rulesOf(stored.Results))
}

// MaxEvents still caps the report when writes retry: the oldest results are dropped.
func TestPolicyReportConcurrentUpdatesKeepMaxEvents(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store, "app")
	c.Config.PolicyReport.MaxEvents = 5

	errs := writeConcurrently(burstOfResults(20, "app"), func(r *wgpolicy.PolicyReportResult) error {
		return c.createOrUpdatePolicyReport(r, "app")
	})

	requireNoErrors(t, errs)
	stored := store.objects[storeKey("app", policyReportName)].(*wgpolicy.PolicyReport)
	require.Len(t, stored.Results, 5)
}

// Another writer (e.g. a second falcosidekick replica) updates the report between our read and our
// write. The in-process lock can't prevent that; the write must be retried on the new version, and
// keep both results.
func TestPolicyReportRetriesAfterAnotherWriter(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store, "app")
	require.NoError(t, c.createOrUpdatePolicyReport(burstOfResults(1, "app")[0], "app"))

	store.otherWriter = func(stored runtime.Object) {
		report := stored.(*wgpolicy.PolicyReport)
		report.Results = append(report.Results, wgpolicy.PolicyReportResult{Rule: "other-writer"})
	}
	ours := &wgpolicy.PolicyReportResult{Rule: "ours", Subjects: []corev1.ObjectReference{{Namespace: "app"}}}

	require.NoError(t, c.createOrUpdatePolicyReport(ours, "app"))
	stored := store.objects[storeKey("app", policyReportName)].(*wgpolicy.PolicyReport)
	require.Equal(t, []string{"rule-00", "other-writer", "ours"}, rulesOf(stored.Results))
}

// The same for the ClusterPolicyReport.
func TestClusterPolicyReportRetriesAfterAnotherWriter(t *testing.T) {
	store := newReportStore()
	c := newConcurrencyTestClient(t, store)
	require.NoError(t, c.createOrUpdateClusterPolicyReport(burstOfResults(1, "")[0]))

	store.otherWriter = func(stored runtime.Object) {
		report := stored.(*wgpolicy.ClusterPolicyReport)
		report.Results = append(report.Results, wgpolicy.PolicyReportResult{Rule: "other-writer"})
	}

	require.NoError(t, c.createOrUpdateClusterPolicyReport(&wgpolicy.PolicyReportResult{Rule: "ours"}))
	stored := store.objects[storeKey("", clusterPolicyReportName)].(*wgpolicy.ClusterPolicyReport)
	require.Equal(t, []string{"rule-00", "other-writer", "ours"}, rulesOf(stored.Results))
}

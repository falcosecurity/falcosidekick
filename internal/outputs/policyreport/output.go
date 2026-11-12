// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package policyreport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "policyreport"

	// defaultMaxResults is also the maximum; maxReportBytes usually keeps fewer.
	defaultMaxResults = 1000
	defaultNamespace  = "default"

	clientQPS   = 50
	clientBurst = 100
	// requestTimeout bounds one API request, like the request timeout of the AWS and SMTP outputs.
	requestTimeout = 30 * time.Second
	// writeStripes bounds the write locks; reports sharing a stripe are written one at a time.
	writeStripes = 64
)

// maxResultsRange bounds max_results; maxReportBytes usually keeps fewer results.
var maxResultsRange = utils.IntRange{Min: 1, Max: defaultMaxResults}

// conflictBackoff spaces the read-modify-write retries against another writer: 10ms, 50ms, 250ms, 1.25s.
var conflictBackoff = retry.DefaultBackoff

var (
	// serviceAccountNamespaceFile holds the namespace of the pod.
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	inClusterConfig             = rest.InClusterConfig
)

type config struct {
	Kubeconfig        string               `mapstructure:"kubeconfig"`
	FallbackNamespace string               `mapstructure:"fallback_namespace"`
	Runtime           output.RuntimeConfig `mapstructure:"runtime"`
	MaxResults        int                  `mapstructure:"max_results"`
	PruneByPriority   bool                 `mapstructure:"prune_by_priority"`
}

// OutputType describes the PolicyReport output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryOther,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{
				Name: "kubeconfig", Type: "string", File: true, Label: "Kubeconfig file (in-cluster configuration when empty)",
				Description: "Path to a kubeconfig file; its current context is used. Empty uses the pod service account.",
			},
			{
				Name: "fallback_namespace", Type: "string", Label: "Namespace for events whose namespace does not exist",
				Description: "Namespace whose `Report` receives events naming a namespace that does not exist. " +
					"Empty uses the pod namespace, else `default`.",
			},
			output.SchemaField{
				Name: "max_results", Type: "int", Default: defaultMaxResults, Label: "Max results per report",
				Description: "Results kept in each report, from `1` to `1000`, also set as `configuration.limits.maxResults`. " +
					"Beyond it the oldest result is removed. A report is also kept within 512 KiB encoded, " +
					"which usually holds fewer results.",
			}.WithIntRange(maxResultsRange),
			{
				Name: "prune_by_priority", Type: "bool", Default: false, Label: "Remove lowest severity results first",
				Description: "When a report is full, removes the oldest result of the lowest severity instead of the oldest result.",
			},
		}, shared.WithDefault(shared.BatchRuntimeConfigSchemaFields(), "runtime.batching.enabled", true)...),
	},
}

type driver struct {
	client    dynamic.Interface
	discovery rest.Interface
	logger    *slog.Logger
	// stripes serialize writes to one report; namespaces come from events, so the set is fixed, not per report.
	stripes [writeStripes]*semaphore.Weighted
	// sleep waits between conflict retries.
	sleep func(ctx context.Context, d time.Duration) error
	// budgetLogged holds the targets already logged as pruned by maxReportBytes.
	budgetLogged sync.Map
	fallback     string
	cfg          config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	maxResultsRange.Check(&errs, "max_results", c.MaxResults)
	if c.FallbackNamespace != "" && len(validation.IsDNS1123Label(c.FallbackNamespace)) > 0 {
		errs.Add("fallback_namespace", "must be a valid namespace name")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if v, ok := raw["max_results"]; !ok || v == nil {
		cfg.MaxResults = defaultMaxResults
	}
	// Batching is on unless runtime.batching.enabled is set: one write per report per flush.
	if cfg.Runtime.Batching == nil {
		cfg.Runtime.Batching = &output.BatchingConfig{}
	}
	if cfg.Runtime.Batching.Enabled == nil {
		cfg.Runtime.Batching.Enabled = new(true)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", name, errs)
	}
	return newDriver(&cfg, nil, deps.Logger), nil
}

// newDriver takes an optional client; Init sets it and the discovery client otherwise.
func newDriver(cfg *config, client dynamic.Interface, logger *slog.Logger) *driver {
	d := &driver{
		cfg:      *cfg,
		client:   client,
		logger:   shared.ResolveLogger(logger, name),
		fallback: fallbackNamespace(cfg.FallbackNamespace),
		sleep:    sleepContext,
	}
	for i := range d.stripes {
		d.stripes[i] = semaphore.NewWeighted(1)
	}
	return d
}

// loadRESTConfig errors never carry the kubeconfig content.
func loadRESTConfig(kubeconfig string) (*rest.Config, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig == "" {
		cfg, err = inClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("%s: kubeconfig: required when not running in a Kubernetes pod", name)
		}
	} else {
		cfg, err = restConfigFromFile(kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("%s: kubeconfig: %w", name, err)
		}
	}
	cfg = rest.CopyConfig(cfg)
	cfg.UserAgent = "falcosidekick"
	cfg.QPS, cfg.Burst = clientQPS, clientBurst
	// client-go sets no request timeout by default; an API server that never answers would hold a worker.
	cfg.Timeout = requestTimeout
	return cfg, nil
}

// restConfigFromFile reads the kubeconfig like every other output file, then resolves its relative
// paths from its directory as client-go's file loader does. Errors never name the path.
func restConfigFromFile(path string) (*rest.Config, error) {
	data, err := utils.ReadRegularFile(path)
	if err != nil {
		return nil, errors.New(utils.FileProblem(err))
	}
	config, err := clientcmd.Load(data)
	if err != nil {
		return nil, errors.New("cannot load file")
	}
	for _, cluster := range config.Clusters {
		cluster.LocationOfOrigin = path
	}
	for _, user := range config.AuthInfos {
		user.LocationOfOrigin = path
	}
	if err := clientcmd.ResolveLocalPaths(config); err != nil {
		return nil, errors.New("cannot load file")
	}
	cfg, err := clientcmd.NewNonInteractiveClientConfig(*config, config.CurrentContext, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, errors.New("cannot load file")
	}
	return cfg, nil
}

// fallbackNamespace is fallback_namespace, else the namespace of the pod, else "default".
func fallbackNamespace(configured string) string {
	if configured != "" {
		return configured
	}
	data, err := os.ReadFile(serviceAccountNamespaceFile)
	if ns := strings.TrimSpace(string(data)); err == nil && len(validation.IsDNS1123Label(ns)) == 0 {
		return ns
	}
	return defaultNamespace
}

func (d *driver) Name() string { return name }

// Init does not contact the API server.
func (d *driver) Init(_ context.Context) error {
	restCfg, err := loadRESTConfig(d.cfg.Kubeconfig)
	if err != nil {
		return err
	}
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("%s: kubeconfig: invalid client configuration", name)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("%s: kubeconfig: invalid client configuration", name)
	}
	d.client, d.discovery = client, disc.RESTClient()
	return nil
}

func (d *driver) Close() error { return nil }

// Send writes one event; with batching disabled each event is one batch.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

// SendBatch reads and writes each report at most once. A result that cannot fit within maxReportBytes
// alone is left out and rejected (output.PartialBatchError); a missing namespace goes to the fallback one.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	groups := make(map[target][]map[string]any)
	var tooLarge []int
	for i, evt := range events {
		result, err := buildResult(evt)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpMarshal, err)
		}
		t := target{namespace: namespaceOf(evt.OutputFields)}
		if _, err := merge(newReport(t), []map[string]any{result}, d.cfg.MaxResults, false); err != nil {
			if !errors.Is(err, errResultTooLarge) {
				return writeError(err)
			}
			tooLarge = append(tooLarge, i)
			continue
		}
		groups[t] = append(groups[t], result)
	}
	if len(tooLarge) == len(events) {
		return errResultTooLarge
	}
	if err := d.write(ctx, groups); err != nil {
		return err
	}
	if len(tooLarge) > 0 {
		return resultsTooLarge(tooLarge, len(events))
	}
	return nil
}

// write applies each report's results, the fallback report last so it also takes the results of missing namespaces.
func (d *driver) write(ctx context.Context, groups map[target][]map[string]any) error {
	fallback := target{namespace: d.fallback}
	targets := make([]target, 0, len(groups))
	for t := range groups {
		if t != fallback {
			targets = append(targets, t)
		}
	}
	slices.SortFunc(targets, func(a, b target) int { return strings.Compare(a.namespace, b.namespace) })
	for _, t := range targets {
		err := d.apply(ctx, t, groups[t])
		if t.namespace != "" && isNamespaceNotFound(err) {
			d.logger.Info("namespace not found, writing to the fallback namespace", "fallback", d.fallback)
			groups[fallback] = append(groups[fallback], groups[t]...)
			continue
		}
		if err != nil {
			return writeError(err)
		}
	}
	if results := groups[fallback]; len(results) > 0 {
		if err := d.apply(ctx, fallback, results); err != nil {
			return writeError(err)
		}
	}
	return nil
}

// resultsTooLarge rejects the events at tooLarge, of a batch of total, whose results were left out.
func resultsTooLarge(tooLarge []int, total int) error {
	failure := *errResultTooLarge
	failure.Code = fmt.Sprintf("%d of %d results %s", len(tooLarge), total, errResultTooLarge.Code)
	failure.Rejected = tooLarge
	return &failure
}

func writeError(err error) error {
	if errors.Is(err, errResultTooLarge) {
		return errResultTooLarge
	}
	return newDeliveryError(opWriteReport, err)
}

// apply serializes local writes per report and retries with backoff when another writer changed it;
// returned to the pipeline, the conflict would count against the circuit breaker and retry the whole batch.
func (d *driver) apply(ctx context.Context, t target, results []map[string]any) error {
	stripe := d.stripe(t)
	if err := stripe.Acquire(ctx, 1); err != nil {
		return err
	}
	defer stripe.Release(1)

	resource := d.resource(t)
	backoff := conflictBackoff
	var err error
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if backoff.Steps < 1 {
				return err
			}
			if sleepErr := d.sleep(ctx, backoff.Step()); sleepErr != nil {
				return sleepErr
			}
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		var obj *unstructured.Unstructured
		obj, err = resource.Get(ctx, reportName, metav1.GetOptions{})
		create := apierrors.IsNotFound(err)
		switch {
		case create:
			obj = newReport(t)
		case err != nil:
			return err
		}
		m, mergeErr := merge(obj, results, d.cfg.MaxResults, d.cfg.PruneByPriority)
		if mergeErr != nil {
			return mergeErr
		}
		if m.budgetPruned > 0 {
			d.logBudget(t, m.kept)
		}
		switch {
		case create:
			_, err = resource.Create(ctx, obj, metav1.CreateOptions{})
		case m.changed:
			_, err = resource.Update(ctx, obj, metav1.UpdateOptions{})
		default:
			return nil
		}
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
}

// logBudget logs once per report that the byte budget, not max_results, sets its size.
func (d *driver) logBudget(t target, kept int) {
	if _, logged := d.budgetLogged.LoadOrStore(t, struct{}{}); logged {
		return
	}
	d.logger.Info("report reached the byte limit, oldest results removed below max_results",
		"namespace", t.namespace, "results", kept, "limit_bytes", maxReportBytes)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *driver) resource(t target) dynamic.ResourceInterface {
	if t.namespace == "" {
		return d.client.Resource(clusterReportsGVR)
	}
	return d.client.Resource(reportsGVR).Namespace(t.namespace)
}

// stripe returns the semaphore of a report: the same report always maps to the same stripe.
func (d *driver) stripe(t target) *semaphore.Weighted {
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.namespace))
	return d.stripes[h.Sum32()%writeStripes]
}

// isNamespaceNotFound reports a create refused because the namespace does not exist.
func isNamespaceNotFound(err error) bool {
	var status apierrors.APIStatus
	if !apierrors.IsNotFound(err) || !errors.As(err, &status) {
		return false
	}
	details := status.Status().Details
	return details != nil && details.Kind == "namespaces"
}

// HealthCheck requires the openreports.io/v1alpha1 API and a readable ClusterReport.
func (d *driver) HealthCheck(ctx context.Context) error {
	if d.client == nil || d.discovery == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	if err := d.checkAPI(ctx); err != nil {
		return err
	}
	_, err := d.client.Resource(clusterReportsGVR).Get(ctx, reportName, metav1.GetOptions{})
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return probeError(opReadClusterReport, err)
}

func (d *driver) checkAPI(ctx context.Context) error {
	raw, err := d.discovery.Get().AbsPath("/apis", group, version).Do(ctx).Raw()
	if err != nil {
		return probeError(opDiscovery, err)
	}
	var list metav1.APIResourceList
	if err := json.Unmarshal(raw, &list); err != nil {
		return newDeliveryError(opDiscovery, err)
	}
	served := make(map[string]bool, len(list.APIResources))
	for i := range list.APIResources {
		served[list.APIResources[i].Name] = true
	}
	for _, resource := range []string{reportsGVR.Resource, clusterReportsGVR.Resource} {
		if !served[resource] {
			return &shared.DeliveryError{
				Output: name, Operation: opDiscovery, Misconfigured: true,
				Code: group + "/" + version + " does not serve " + resource,
			}
		}
	}
	return nil
}

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
	"strings"
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

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "policyreport"

	defaultMaxEvents = 1000
	defaultNamespace = "default"

	// maxAttempts bounds read-modify-write retries against concurrent writers.
	maxAttempts = 5

	clientQPS   = 50
	clientBurst = 100
	// requestTimeout bounds one API request, like the request timeout of the AWS and SMTP outputs.
	requestTimeout = 30 * time.Second
	// writeStripes bounds the write locks; reports sharing a stripe are written one at a time.
	writeStripes = 64
)

var (
	// serviceAccountNamespaceFile holds the namespace of the pod.
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	inClusterConfig             = rest.InClusterConfig
)

type config struct {
	Kubeconfig      string               `mapstructure:"kubeconfig"`
	FalcoNamespace  string               `mapstructure:"falco_namespace"`
	Runtime         output.RuntimeConfig `mapstructure:"runtime"`
	MaxEvents       int                  `mapstructure:"max_events"`
	PruneByPriority bool                 `mapstructure:"prune_by_priority"`
}

// OutputType describes the PolicyReport output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryOther,
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "kubeconfig", Type: "string", File: true, Label: "Kubeconfig file (in-cluster configuration when empty)"},
			{Name: "falco_namespace", Type: "string", Label: "Namespace for events whose namespace does not exist"},
			{Name: "max_events", Type: "int", Default: defaultMaxEvents, Label: "Max results per report"},
			{Name: "prune_by_priority", Type: "bool", Default: false, Label: "Remove lowest severity results first"},
		}, shared.RuntimeConfigSchemaFields()...),
	},
}

type driver struct {
	client    dynamic.Interface
	discovery rest.Interface
	logger    *slog.Logger
	// stripes serialize writes to one report; namespaces come from events, so the set is fixed, not per report.
	stripes  [writeStripes]*semaphore.Weighted
	fallback string
	cfg      config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.MaxEvents < 1 {
		errs.Add("max_events", "must be at least 1")
	}
	if c.FalcoNamespace != "" && len(validation.IsDNS1123Label(c.FalcoNamespace)) > 0 {
		errs.Add("falco_namespace", "must be a valid namespace name")
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
	if _, ok := raw["max_events"]; !ok {
		cfg.MaxEvents = defaultMaxEvents
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}
	return newDriver(&cfg, nil, nil, deps.Logger), nil
}

func newDriver(cfg *config, client dynamic.Interface, disc rest.Interface, logger *slog.Logger) *driver {
	d := &driver{
		cfg:       *cfg,
		client:    client,
		discovery: disc,
		logger:    shared.ResolveLogger(logger, name),
		fallback:  fallbackNamespace(cfg.FalcoNamespace),
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

// fallbackNamespace is falco_namespace, else the namespace of the pod, else "default".
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

// Send uses the fallback namespace when the event namespace does not exist.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	if d.client == nil {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	result, err := buildResult(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}
	t := target{namespace: namespaceOf(evt.OutputFields)}
	err = d.apply(ctx, t, result)
	if t.namespace != "" && t.namespace != d.fallback && isNamespaceNotFound(err) {
		d.logger.Info("namespace not found, writing to the fallback namespace", "fallback", d.fallback)
		err = d.apply(ctx, target{namespace: d.fallback}, result)
	}
	if err != nil {
		return newDeliveryError(opWriteReport, err)
	}
	return nil
}

// apply serializes local writes per report and retries when another writer changed it in between.
func (d *driver) apply(ctx context.Context, t target, result map[string]any) error {
	stripe := d.stripe(t)
	if err := stripe.Acquire(ctx, 1); err != nil {
		return err
	}
	defer stripe.Release(1)

	resource := d.resource(t)
	var err error
	for range maxAttempts {
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
		addResult(obj, result, d.cfg.MaxEvents, d.cfg.PruneByPriority)
		if create {
			_, err = resource.Create(ctx, obj, metav1.CreateOptions{})
		} else {
			_, err = resource.Update(ctx, obj, metav1.UpdateOptions{})
		}
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	return err
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

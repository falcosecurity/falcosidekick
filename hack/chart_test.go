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

package hacktesting

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
)

const (
	chartDir           = "../chart/falcosidekick"
	chartRelease       = "fsk"
	chartFullname      = "fsk-falcosidekick"
	chartNamespace     = "falco"
	chartSkipNoHelmEnv = "FSK_CHART_TEST_SKIP_NO_HELM"
	chartTLSSecret     = "fsk-tls"
	chartUserTLSSecret = "user-tls"
	chartUserTLSDir    = "/etc/falcosidekick/user-tls"
	chartPGSecret      = "pg-auth"
	chartUserSecretDir = "/custom/dir"
	chartWebhookHost   = "http://receiver.falco.svc:8080"
	chartExtraOutputs  = "more-outputs"
	chartSentinel      = "SENTINEL-c0ffee"

	errSlimUI         = "image.variant slim has no web UI"
	errSQLiteReplicas = "database.backend sqlite supports replicaCount 1 only"

	dbSQLite   = "sqlite"
	dbPostgres = "postgres"
	tlsOff     = "off"
	tlsSecret  = "secret"
	tlsMutual  = "mutual"
	tlsFiles   = "files"

	variantSlim = "slim"

	// The defaults of a pod: 5s of shutdown_delay plus 15s; 30s of connect_timeout plus 30s, in periods of 5s.
	defaultGracePeriod      = 20
	defaultStartupThreshold = 12
)

type chartCase struct {
	variant        string
	database       string
	tls            string
	secrets        []string
	replicas       int
	ui             bool
	management     bool
	serviceMonitor bool
	policyReport   bool
	extraOutputs   bool
}

func (c *chartCase) String() string {
	return fmt.Sprintf("ui=%t variant=%q database=%s replicas=%d tls=%s management=%t serviceMonitor=%t policyReport=%t secrets=%v extraOutputs=%t",
		c.ui, c.variant, c.database, c.replicas, c.tls, c.management, c.serviceMonitor, c.policyReport, c.secrets, c.extraOutputs)
}

// chartCases is the cartesian product of every axis.
func chartCases() []chartCase {
	cases := make([]chartCase, 0, 3072)
	for _, ui := range []bool{true, false} {
		for _, variant := range []string{"", variantSlim} {
			for _, database := range []string{"inmemory", dbSQLite, dbPostgres} {
				for _, replicas := range []int{1, 2} {
					for _, tls := range []string{tlsOff, tlsSecret, tlsMutual, tlsFiles} {
						for _, management := range []bool{true, false} {
							for _, serviceMonitor := range []bool{true, false} {
								for _, policyReport := range []bool{true, false} {
									for _, secrets := range [][]string{nil, {"a", "b"}} {
										for _, extraOutputs := range []bool{true, false} {
											cases = append(cases, chartCase{
												ui: ui, variant: variant, database: database, replicas: replicas, tls: tls,
												management: management, serviceMonitor: serviceMonitor, policyReport: policyReport,
												secrets: secrets, extraOutputs: extraOutputs,
											})
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return cases
}

// expectedErrors are the messages rendering must fail with; none means the values are valid.
func (c *chartCase) expectedErrors() []string {
	var errs []string
	if c.ui && c.variant == variantSlim {
		errs = append(errs, errSlimUI)
	}
	if c.database == dbSQLite && c.replicas > 1 {
		errs = append(errs, errSQLiteReplicas)
	}
	return errs
}

func (c *chartCase) values() map[string]any {
	sidekick := map[string]any{
		"log_format": "json",
		"enricher":   map[string]any{"custom_tags": []string{"team-a"}},
		"api":        map[string]any{"secret_dirs": []string{chartUserSecretDir}},
	}
	values := map[string]any{
		"replicaCount":   c.replicas,
		"image":          map[string]any{"variant": c.variant},
		"ui":             map[string]any{"enabled": c.ui},
		"database":       map[string]any{"backend": c.database},
		"management":     map[string]any{"service": map[string]any{"enabled": c.management}},
		"serviceMonitor": map[string]any{"enabled": c.serviceMonitor},
		"rbac":           map[string]any{"policyReport": c.policyReport},
		"secrets":        c.secrets,
		"config":         sidekick,
		"outputs":        map[string]any{"webhook": map[string]any{"host": chartWebhookHost, "endpoint": "/falco"}},
	}
	switch c.tls {
	case tlsSecret, tlsMutual:
		sidekick["tls"] = map[string]any{"enabled": true, "mutual_tls": c.tls == tlsMutual}
		values["tls"] = map[string]any{"secretName": chartTLSSecret}
	case tlsFiles:
		sidekick["tls"] = map[string]any{"enabled": true, "cert_file": chartUserTLSDir + "/tls.crt", "key_file": chartUserTLSDir + "/tls.key"}
		values["extraVolumes"] = []any{map[string]any{"name": "user-tls", "secret": map[string]any{"secretName": chartUserTLSSecret}}}
		values["extraVolumeMounts"] = []any{map[string]any{"name": "user-tls", "mountPath": chartUserTLSDir, "readOnly": true}}
	}
	if c.database == dbPostgres {
		sidekick["database"] = map[string]any{"postgres": map[string]any{
			"host": "postgres.falco.svc", "database": "falcosidekick", "user": "falcosidekick",
		}}
		values["database"].(map[string]any)["postgres"] = map[string]any{"passwordSecret": map[string]any{"name": chartPGSecret}}
	}
	if c.extraOutputs {
		values["extraOutputConfigMaps"] = []any{map[string]any{"name": chartExtraOutputs}}
	}
	return values
}

type k8sObject struct {
	Metadata k8sMeta `yaml:"metadata"`
	Kind     string  `yaml:"kind"`
}

type k8sMeta struct {
	Annotations map[string]string `yaml:"annotations"`
	Labels      map[string]string `yaml:"labels"`
	Name        string            `yaml:"name"`
}

type k8sSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

type k8sDeployment struct {
	Spec struct {
		Selector k8sSelector `yaml:"selector"`
		Strategy struct {
			Type string `yaml:"type"`
		} `yaml:"strategy"`
		Template struct {
			Metadata k8sMeta    `yaml:"metadata"`
			Spec     k8sPodSpec `yaml:"spec"`
		} `yaml:"template"`
		Replicas int `yaml:"replicas"`
	} `yaml:"spec"`
}

type k8sPodSpec struct {
	SecurityContext struct {
		RunAsNonRoot   *bool  `yaml:"runAsNonRoot"`
		RunAsUser      *int64 `yaml:"runAsUser"`
		RunAsGroup     *int64 `yaml:"runAsGroup"`
		FSGroup        *int64 `yaml:"fsGroup"`
		SeccompProfile struct {
			Type string `yaml:"type"`
		} `yaml:"seccompProfile"`
	} `yaml:"securityContext"`
	TerminationGracePeriodSeconds *int64         `yaml:"terminationGracePeriodSeconds"`
	AutomountServiceAccountToken  *bool          `yaml:"automountServiceAccountToken"`
	ServiceAccountName            string         `yaml:"serviceAccountName"`
	PriorityClassName             string         `yaml:"priorityClassName"`
	RestartPolicy                 string         `yaml:"restartPolicy"`
	Containers                    []k8sContainer `yaml:"containers"`
	Volumes                       []k8sVolume    `yaml:"volumes"`
}

type k8sContainer struct {
	SecurityContext struct {
		RunAsNonRoot             *bool  `yaml:"runAsNonRoot"`
		RunAsUser                *int64 `yaml:"runAsUser"`
		ReadOnlyRootFilesystem   *bool  `yaml:"readOnlyRootFilesystem"`
		AllowPrivilegeEscalation *bool  `yaml:"allowPrivilegeEscalation"`
		Capabilities             struct {
			Drop []string `yaml:"drop"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
	Resources struct {
		Requests map[string]string `yaml:"requests"`
		Limits   map[string]string `yaml:"limits"`
	} `yaml:"resources"`
	StartupProbe   *k8sProbe `yaml:"startupProbe"`
	LivenessProbe  *k8sProbe `yaml:"livenessProbe"`
	ReadinessProbe *k8sProbe `yaml:"readinessProbe"`
	Name           string    `yaml:"name"`
	Image          string    `yaml:"image"`
	Command        []string  `yaml:"command"`
	Args           []string  `yaml:"args"`
	Env            []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	Ports []struct {
		Name          string `yaml:"name"`
		Protocol      string `yaml:"protocol"`
		ContainerPort int    `yaml:"containerPort"`
	} `yaml:"ports"`
	VolumeMounts []k8sVolumeMount `yaml:"volumeMounts"`
}

type k8sVolumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type k8sProbe struct {
	HTTPGet struct {
		Path   string `yaml:"path"`
		Scheme string `yaml:"scheme"`
		Port   int    `yaml:"port"`
	} `yaml:"httpGet"`
	PeriodSeconds    int `yaml:"periodSeconds"`
	TimeoutSeconds   int `yaml:"timeoutSeconds"`
	FailureThreshold int `yaml:"failureThreshold"`
}

type k8sVolume struct {
	Secret *struct {
		SecretName string `yaml:"secretName"`
	} `yaml:"secret"`
	ConfigMap *struct {
		Name string `yaml:"name"`
	} `yaml:"configMap"`
	PersistentVolumeClaim *struct {
		ClaimName string `yaml:"claimName"`
	} `yaml:"persistentVolumeClaim"`
	Name string `yaml:"name"`
}

// source names what a volume holds, such as secret/fsk-tls.
func (v *k8sVolume) source() string {
	switch {
	case v.Secret != nil:
		return "secret/" + v.Secret.SecretName
	case v.ConfigMap != nil:
		return "configmap/" + v.ConfigMap.Name
	case v.PersistentVolumeClaim != nil:
		return "pvc/" + v.PersistentVolumeClaim.ClaimName
	}
	return "unknown"
}

type k8sService struct {
	Metadata k8sMeta `yaml:"metadata"`
	Spec     struct {
		Selector       map[string]string `yaml:"selector"`
		IPFamilyPolicy string            `yaml:"ipFamilyPolicy"`
		IPFamilies     []string          `yaml:"ipFamilies"`
		Ports          []struct {
			Name       string `yaml:"name"`
			TargetPort string `yaml:"targetPort"`
			Port       int    `yaml:"port"`
		} `yaml:"ports"`
	} `yaml:"spec"`
}

type k8sServiceMonitor struct {
	Spec struct {
		Selector  k8sSelector `yaml:"selector"`
		Endpoints []struct {
			Port   string `yaml:"port"`
			Path   string `yaml:"path"`
			Scheme string `yaml:"scheme"`
		} `yaml:"endpoints"`
	} `yaml:"spec"`
}

type k8sPDB struct {
	Spec struct {
		MinAvailable   any         `yaml:"minAvailable"`
		MaxUnavailable any         `yaml:"maxUnavailable"`
		Selector       k8sSelector `yaml:"selector"`
	} `yaml:"spec"`
}

type k8sPod struct {
	Metadata k8sMeta    `yaml:"metadata"`
	Spec     k8sPodSpec `yaml:"spec"`
}

type k8sRule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames"`
	Verbs         []string `yaml:"verbs"`
}

type k8sClusterRole struct {
	Rules []k8sRule `yaml:"rules"`
}

type k8sClusterRoleBinding struct {
	RoleRef struct {
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
}

// policyReportRules are the only permissions of the policyreport ClusterRole.
var policyReportRules = []k8sRule{
	{APIGroups: []string{"openreports.io"}, Resources: []string{"reports", "clusterreports"}, Verbs: []string{"create"}},
	{
		APIGroups: []string{"openreports.io"}, Resources: []string{"reports", "clusterreports"},
		ResourceNames: []string{"falcosidekick"}, Verbs: []string{"get", "update"},
	},
}

// chartRender holds the rendered documents by kind, each keyed by name.
type chartRender map[string]map[string][]byte

func parseChartRender(out []byte) (chartRender, error) {
	objs := chartRender{}
	for doc := range strings.SplitSeq("\n"+string(out), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj k8sObject
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		if obj.Kind == "" {
			continue
		}
		if objs[obj.Kind] == nil {
			objs[obj.Kind] = map[string][]byte{}
		}
		objs[obj.Kind][obj.Metadata.Name] = []byte(doc)
	}
	return objs, nil
}

// decode reads the object of that kind and name into target, and reports whether it exists.
func (r chartRender) decode(kind, name string, target any) (bool, error) {
	doc, ok := r[kind][name]
	if !ok {
		return false, nil
	}
	return true, yaml.Unmarshal(doc, target)
}

func (r chartRender) configData() (map[string]string, error) {
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	ok, err := r.decode("ConfigMap", chartFullname, &cm)
	if err != nil {
		return nil, fmt.Errorf("ConfigMap %s: %w", chartFullname, err)
	}
	if !ok {
		return nil, fmt.Errorf("ConfigMap %s: missing", chartFullname)
	}
	return cm.Data, nil
}

func (r chartRender) configFile(file string) (map[string]any, error) {
	data, err := r.configData()
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = yaml.Unmarshal([]byte(data[file]), &out)
	return out, err
}

func requireHelm(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv(chartSkipNoHelmEnv) == "1" {
			t.Skipf("helm not found and %s=1", chartSkipNoHelmEnv)
		}
		t.Fatalf("helm not found: install it, or set %s=1 to skip the chart tests", chartSkipNoHelmEnv)
	}
	return helm
}

func chartAppVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	require.NoError(t, err)
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	require.NoError(t, yaml.Unmarshal(data, &chart))
	require.NotEmpty(t, chart.AppVersion)
	return chart.AppVersion
}

// renderChart runs helm template with the values on stdin; a failed render returns its stderr in the error.
func renderChart(ctx context.Context, helm string, values map[string]any) (chartRender, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, helm, "template", chartRelease, chartDir, "--namespace", chartNamespace, "--values", "-")
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return parseChartRender(stdout.Bytes())
}

type checker struct{ problems []string }

func (c *checker) expectf(ok bool, format string, args ...any) {
	if !ok {
		c.problems = append(c.problems, fmt.Sprintf(format, args...))
	}
}

func (c *checker) equal(name string, want, got any) {
	c.expectf(reflect.DeepEqual(want, got), "%s: want %#v, got %#v", name, want, got)
}

func (c *checker) noError(name string, err error) {
	c.expectf(err == nil, "%s: %v", name, err)
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, key := range keys {
		next, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = next[key]
	}
	return cur
}

func isTrue(b *bool) bool { return b != nil && *b }

func is65532(v *int64) bool { return v != nil && *v == 65532 }

// selects reports whether a selector picks objects with these labels.
func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// runtimeFixture holds the files a rendered configuration names, created once: a certificate and
// key, a CA, a postgres password, and the extra output file a ConfigMap of extraOutputConfigMaps holds.
type runtimeFixture struct {
	cat   *catalog.Catalog
	files map[string]string
	dir   string
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: chartFullname},
		DNSNames:  []string{chartFullname + "." + chartNamespace + ".svc"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	contents := map[string][]byte{
		"cert_file":     cert,
		"ca_file":       cert,
		"key_file":      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"password_file": []byte("pg-password\n"),
		"extra_outputs": []byte("outputs:\n  webhook:\n    endpoint: /extra\n"),
	}
	files := map[string]string{}
	for name, content := range contents {
		files[name] = filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(files[name], content, 0o600))
	}
	cat, err := catalog.New(all.Types())
	require.NoError(t, err)
	return &runtimeFixture{cat: cat, files: files, dir: dir}
}

// mountedAt reports whether a file path lies under a volume mount of the container.
func mountedAt(container *k8sContainer, file string) bool {
	for _, m := range container.VolumeMounts {
		if strings.HasPrefix(file, strings.TrimSuffix(m.MountPath, "/")+"/") {
			return true
		}
	}
	return false
}

// loadWithRuntime runs the rendered files through the process's own loaders: every file a setting
// names must sit under a mount, and is replaced by a fixture so the strict loader and the
// validation see real files.
func (f *runtimeFixture) loadWithRuntime(ch *checker, data map[string]string, container *k8sContainer) {
	var sidekick map[string]any
	if err := yaml.Unmarshal([]byte(data["sidekick.yaml"]), &sidekick); err != nil {
		ch.noError("sidekick.yaml", err)
		return
	}
	for _, keys := range [][]string{
		{"tls", "cert_file"}, {"tls", "key_file"}, {"tls", "ca_file"}, {"database", "postgres", "password_file"},
	} {
		file, ok := dig(sidekick, keys...).(string)
		if !ok {
			continue
		}
		ch.expectf(mountedAt(container, file), "%s %s: no volume is mounted there", strings.Join(keys, "."), file)
		parent, _ := dig(sidekick, keys[:len(keys)-1]...).(map[string]any)
		parent[keys[len(keys)-1]] = f.files[keys[len(keys)-1]]
	}
	if sqlitePath, ok := dig(sidekick, "database", "sqlite", "path").(string); ok {
		ch.expectf(mountedAt(container, sqlitePath), "database.sqlite.path %s: no volume is mounted there", sqlitePath)
	}

	dir, err := os.MkdirTemp(f.dir, "case")
	if err != nil {
		ch.noError("temp dir", err)
		return
	}
	rewritten, err := yaml.Marshal(sidekick)
	ch.noError("sidekick.yaml", err)
	sidekickPath := filepath.Join(dir, "sidekick.yaml")
	ch.noError("sidekick.yaml", os.WriteFile(sidekickPath, rewritten, 0o600))
	cfg, err := config.Load(sidekickPath)
	if err != nil {
		ch.noError("config.Load", err)
		return
	}
	if errs := cfg.Validate(); len(errs) > 0 {
		ch.expectf(false, "config validation: %s", errs.Error())
	}

	// The output files in the order of the -o arguments.
	var outputPaths []string
	for i, arg := range container.Args {
		if arg != "-o" || i+1 >= len(container.Args) {
			continue
		}
		file := container.Args[i+1]
		ch.expectf(mountedAt(container, file), "-o %s: no volume is mounted there", file)
		switch {
		case file == "/etc/falcosidekick/config/outputs.yaml":
			local := filepath.Join(dir, "outputs.yaml")
			ch.noError("outputs.yaml", os.WriteFile(local, []byte(data["outputs.yaml"]), 0o600))
			outputPaths = append(outputPaths, local)
		case strings.HasPrefix(file, "/etc/falcosidekick/outputs/"):
			outputPaths = append(outputPaths, f.files["extra_outputs"])
		default:
			ch.expectf(false, "-o %s: unexpected file", file)
		}
	}
	outputs, err := config.LoadOutputs(outputPaths)
	if err != nil {
		ch.noError("config.LoadOutputs", err)
		return
	}
	ch.noError("ui.event_source", config.CheckEventSource(&cfg.UI, f.cat))
	if cfg.Database.Backend.Persistent() {
		ch.noError("inline secrets", config.CheckNoInlineSecrets(outputs.Outputs, f.cat))
	}
	resolved, err := config.ResolvedOutputs(outputs.Outputs, f.cat)
	if err != nil {
		ch.noError("secret resolution", err)
		return
	}
	for _, name := range slices.Sorted(maps.Keys(resolved)) {
		driver, err := f.cat.Create(name, resolved[name], output.Deps{Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			ch.noError("output "+name, err)
			continue
		}
		ch.noError("close "+name, driver.Close())
	}
	if len(outputPaths) > 1 {
		ch.equal("merged webhook", map[string]any{"host": chartWebhookHost, "endpoint": "/extra"}, outputs.Outputs["webhook"])
	}
}

func (c *chartCase) check(r chartRender, appVersion string, fixture *runtimeFixture) []string {
	ch := &checker{}
	data, err := r.configData()
	ch.noError("ConfigMap", err)
	sidekick, err := r.configFile("sidekick.yaml")
	ch.noError("sidekick.yaml", err)
	outputs, err := r.configFile("outputs.yaml")
	ch.noError("outputs.yaml", err)

	var deploy k8sDeployment
	found, err := r.decode("Deployment", chartFullname, &deploy)
	if !found || err != nil {
		return append(ch.problems, fmt.Sprintf("Deployment %s: found=%t err=%v", chartFullname, found, err))
	}
	pod := &deploy.Spec.Template.Spec
	if len(pod.Containers) != 1 {
		return append(ch.problems, fmt.Sprintf("want one container, got %d", len(pod.Containers)))
	}
	container := &pod.Containers[0]
	tls := c.tls != tlsOff

	c.checkSecurity(ch, pod, container)
	c.checkProbesAndPorts(ch, r, container, tls)
	c.checkVolumes(ch, pod, container)
	c.checkSecrets(ch, sidekick)
	c.checkUserConfig(ch, sidekick, outputs)
	c.checkTLS(ch, sidekick)
	c.checkDatabase(ch, r, sidekick, &deploy)
	c.checkOptionalObjects(ch, r, sidekick, pod, tls)
	c.checkSelectors(ch, r, &deploy)
	c.checkUI(ch, sidekick, outputs)
	c.checkTestPod(ch, r, tls)
	fixture.loadWithRuntime(ch, data, container)

	ch.equal("replicas", c.replicas, deploy.Spec.Replicas)
	ch.equal("container name", "falcosidekick", container.Name)
	wantArgs := []string{"-c", "/etc/falcosidekick/config/sidekick.yaml", "-o", "/etc/falcosidekick/config/outputs.yaml"}
	if c.extraOutputs {
		wantArgs = append(wantArgs, "-o", "/etc/falcosidekick/outputs/"+chartExtraOutputs+"/outputs.yaml")
	}
	ch.equal("args", wantArgs, container.Args)
	wantImage := "docker.io/falcosecurity/falcosidekick:" + appVersion
	if c.variant != "" {
		wantImage += "-" + c.variant
	}
	ch.equal("image", wantImage, container.Image)
	ch.equal("resources.requests", map[string]string{"cpu": "50m", "memory": "64Mi"}, container.Resources.Requests)
	ch.equal("resources.limits", map[string]string{"memory": "512Mi"}, container.Resources.Limits)
	ch.equal("priorityClassName", "", pod.PriorityClassName)
	grace := int64(-1)
	if pod.TerminationGracePeriodSeconds != nil {
		grace = *pod.TerminationGracePeriodSeconds
	}
	ch.equal("terminationGracePeriodSeconds", int64(defaultGracePeriod), grace)

	sum := sha256.Sum256([]byte(data["sidekick.yaml"]))
	ch.equal("checksum/config annotation", hex.EncodeToString(sum[:]), deploy.Spec.Template.Metadata.Annotations["checksum/config"])
	return ch.problems
}

func (c *chartCase) checkSecurity(ch *checker, pod *k8sPodSpec, container *k8sContainer) {
	psc := pod.SecurityContext
	ch.expectf(isTrue(psc.RunAsNonRoot), "pod runAsNonRoot: want true")
	ch.expectf(is65532(psc.RunAsUser), "pod runAsUser: want 65532")
	ch.expectf(is65532(psc.RunAsGroup), "pod runAsGroup: want 65532")
	ch.expectf(is65532(psc.FSGroup), "pod fsGroup: want 65532")
	ch.equal("pod seccompProfile", "RuntimeDefault", psc.SeccompProfile.Type)
	csc := container.SecurityContext
	ch.expectf(isTrue(csc.RunAsNonRoot), "container runAsNonRoot: want true")
	ch.expectf(is65532(csc.RunAsUser), "container runAsUser: want 65532")
	ch.expectf(isTrue(csc.ReadOnlyRootFilesystem), "readOnlyRootFilesystem: want true")
	ch.expectf(csc.AllowPrivilegeEscalation != nil && !*csc.AllowPrivilegeEscalation, "allowPrivilegeEscalation: want false")
	ch.equal("capabilities.drop", []string{"ALL"}, csc.Capabilities.Drop)
}

// urlScheme is the scheme the chart serves with TLS on or off.
func urlScheme(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}

func (c *chartCase) checkProbesAndPorts(ch *checker, r chartRender, container *k8sContainer, tls bool) {
	scheme := strings.ToUpper(urlScheme(tls))
	for _, probe := range []struct {
		probe                    *k8sProbe
		name, path               string
		period, timeout, failure int
	}{
		{container.StartupProbe, "startupProbe", "/livez", 5, 3, defaultStartupThreshold},
		{container.LivenessProbe, "livenessProbe", "/livez", 10, 3, 3},
		{container.ReadinessProbe, "readinessProbe", "/readyz", 5, 3, 3},
	} {
		if probe.probe == nil {
			ch.expectf(false, "%s: missing", probe.name)
			continue
		}
		ch.equal(probe.name+" path", probe.path, probe.probe.HTTPGet.Path)
		ch.equal(probe.name+" port", 2801, probe.probe.HTTPGet.Port)
		ch.equal(probe.name+" scheme", scheme, probe.probe.HTTPGet.Scheme)
		ch.equal(probe.name+" timings", []int{probe.period, probe.timeout, probe.failure},
			[]int{probe.probe.PeriodSeconds, probe.probe.TimeoutSeconds, probe.probe.FailureThreshold})
	}

	portNames := map[int]string{}
	for _, port := range container.Ports {
		ch.equal(fmt.Sprintf("port %d protocol", port.ContainerPort), "TCP", port.Protocol)
		portNames[port.ContainerPort] = port.Name
	}
	ch.expectf(len(container.Ports) == 2 && portNames[2801] != "" && portNames[2802] != "",
		"container ports: want 2801 and 2802, got %v", portNames)

	var svc k8sService
	found, err := r.decode("Service", chartFullname, &svc)
	ch.expectf(found && err == nil, "Service %s: found=%t err=%v", chartFullname, found, err)
	ch.expectf(len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].Port == 2801 && svc.Spec.Ports[0].TargetPort == portNames[2801],
		"Service ports: want 2801 to container port %q, got %+v", portNames[2801], svc.Spec.Ports)
	ch.expectf(svc.Spec.IPFamilyPolicy == "" && svc.Spec.IPFamilies == nil, "Service ip families: want the cluster default")

	var mgmt k8sService
	found, err = r.decode("Service", chartFullname+"-management", &mgmt)
	ch.noError("management Service", err)
	ch.equal("management Service present", c.management, found)
	if found {
		ch.expectf(len(mgmt.Spec.Ports) == 1 && mgmt.Spec.Ports[0].Port == 2802 && mgmt.Spec.Ports[0].TargetPort == portNames[2802],
			"management Service ports: want 2802 to container port %q, got %+v", portNames[2802], mgmt.Spec.Ports)
	}
	ch.equal("Service count", map[bool]int{true: 2, false: 1}[c.management], len(r["Service"]))
}

// checkVolumes requires every mount to name a volume and every volume to be mounted once, at the
// path of its role, read-only except the sqlite data.
func (c *chartCase) checkVolumes(ch *checker, pod *k8sPodSpec, container *k8sContainer) {
	want := map[string]k8sVolumeMount{
		"configmap/" + chartFullname: {MountPath: "/etc/falcosidekick/config", ReadOnly: true},
	}
	for _, name := range c.secrets {
		want["secret/"+name] = k8sVolumeMount{MountPath: "/etc/falcosidekick/secrets/" + name, ReadOnly: true}
	}
	switch c.tls {
	case tlsSecret, tlsMutual:
		want["secret/"+chartTLSSecret] = k8sVolumeMount{MountPath: "/etc/falcosidekick/tls", ReadOnly: true}
	case tlsFiles:
		want["secret/"+chartUserTLSSecret] = k8sVolumeMount{MountPath: chartUserTLSDir, ReadOnly: true}
	}
	switch c.database {
	case dbSQLite:
		want["pvc/"+chartFullname+"-data"] = k8sVolumeMount{MountPath: "/var/lib/falcosidekick"}
	case dbPostgres:
		want["secret/"+chartPGSecret] = k8sVolumeMount{MountPath: "/etc/falcosidekick/postgres", ReadOnly: true}
	}
	if c.extraOutputs {
		want["configmap/"+chartExtraOutputs] = k8sVolumeMount{MountPath: "/etc/falcosidekick/outputs/" + chartExtraOutputs, ReadOnly: true}
	}

	volumes := map[string]string{}
	for i := range pod.Volumes {
		v := &pod.Volumes[i]
		_, dup := volumes[v.Name]
		ch.expectf(!dup, "volume %s: defined twice", v.Name)
		volumes[v.Name] = v.source()
	}
	got := map[string]k8sVolumeMount{}
	paths := map[string]bool{}
	for _, m := range container.VolumeMounts {
		source, ok := volumes[m.Name]
		ch.expectf(ok, "mount %s: no volume of that name", m.Name)
		ch.expectf(!paths[m.MountPath], "mount path %s: used twice", m.MountPath)
		paths[m.MountPath] = true
		_, dup := got[source]
		ch.expectf(!dup, "volume %s: mounted twice", source)
		got[source] = k8sVolumeMount{MountPath: m.MountPath, ReadOnly: m.ReadOnly}
	}
	ch.equal("volume mounts", want, got)
	ch.equal("volume count", len(want), len(volumes))
}

func (c *chartCase) checkSecrets(ch *checker, sidekick map[string]any) {
	wantDirs := make([]any, 0, 1+len(c.secrets))
	wantDirs = append(wantDirs, chartUserSecretDir)
	for _, name := range c.secrets {
		wantDirs = append(wantDirs, "/etc/falcosidekick/secrets/"+name)
	}
	ch.equal("api.secret_dirs", wantDirs, dig(sidekick, "api", "secret_dirs"))
}

func (c *chartCase) checkUserConfig(ch *checker, sidekick, outputs map[string]any) {
	ch.equal("log_format", "json", dig(sidekick, "log_format"))
	ch.equal("enricher.custom_tags", []any{"team-a"}, dig(sidekick, "enricher", "custom_tags"))
	ch.equal("outputs.webhook", map[string]any{"host": chartWebhookHost, "endpoint": "/falco"}, dig(outputs, "outputs", "webhook"))
}

func (c *chartCase) checkTLS(ch *checker, sidekick map[string]any) {
	switch c.tls {
	case tlsOff:
		ch.equal("tls", nil, dig(sidekick, "tls"))
		return
	case tlsFiles:
		ch.equal("tls", map[string]any{"enabled": true, "cert_file": chartUserTLSDir + "/tls.crt", "key_file": chartUserTLSDir + "/tls.key"},
			dig(sidekick, "tls"))
		return
	}
	want := map[string]any{
		"enabled": true, "mutual_tls": c.tls == tlsMutual,
		"cert_file": "/etc/falcosidekick/tls/tls.crt", "key_file": "/etc/falcosidekick/tls/tls.key",
	}
	if c.tls == tlsMutual {
		want["ca_file"] = "/etc/falcosidekick/tls/ca.crt"
	}
	ch.equal("tls", want, dig(sidekick, "tls"))
}

func (c *chartCase) checkDatabase(ch *checker, r chartRender, sidekick map[string]any, deploy *k8sDeployment) {
	sqlite := c.database == dbSQLite
	ch.equal("database.backend", c.database, dig(sidekick, "database", "backend"))

	var pvc k8sObject
	found, err := r.decode("PersistentVolumeClaim", chartFullname+"-data", &pvc)
	ch.noError("PersistentVolumeClaim", err)
	ch.equal("PersistentVolumeClaim present", sqlite, found)
	ch.equal("PersistentVolumeClaim count", map[bool]int{true: 1, false: 0}[sqlite], len(r["PersistentVolumeClaim"]))
	if found {
		ch.equal("PersistentVolumeClaim resource-policy", "keep", pvc.Metadata.Annotations["helm.sh/resource-policy"])
	}
	if sqlite {
		ch.equal("database.sqlite", map[string]any{"path": "/var/lib/falcosidekick/sidekick.db"}, dig(sidekick, "database", "sqlite"))
		ch.equal("strategy", "Recreate", deploy.Spec.Strategy.Type)
	} else {
		ch.expectf(deploy.Spec.Strategy.Type != "Recreate", "strategy: want rolling update without sqlite")
	}
	if c.database == dbPostgres {
		ch.equal("database.postgres", map[string]any{
			"host": "postgres.falco.svc", "database": "falcosidekick", "user": "falcosidekick",
			"password_file": "/etc/falcosidekick/postgres/password",
		}, dig(sidekick, "database", "postgres"))
	} else {
		ch.equal("database.postgres", nil, dig(sidekick, "database", "postgres"))
	}
}

func (c *chartCase) checkOptionalObjects(ch *checker, r chartRender, sidekick map[string]any, pod *k8sPodSpec, tls bool) {
	var sm k8sServiceMonitor
	found, err := r.decode("ServiceMonitor", chartFullname, &sm)
	ch.noError("ServiceMonitor", err)
	ch.equal("ServiceMonitor present", c.serviceMonitor, found)
	ch.equal("ServiceMonitor count", map[bool]int{true: 1, false: 0}[c.serviceMonitor], len(r["ServiceMonitor"]))
	if found {
		scheme := urlScheme(tls)
		ok := len(sm.Spec.Endpoints) == 1 && sm.Spec.Endpoints[0].Path == "/metrics" &&
			sm.Spec.Endpoints[0].Scheme == scheme && sm.Spec.Endpoints[0].Port == scheme
		ch.expectf(ok, "ServiceMonitor endpoints: want /metrics over %s, got %+v", scheme, sm.Spec.Endpoints)
	}

	ch.expectf(len(r["ServiceAccount"][chartFullname]) > 0, "ServiceAccount %s: missing", chartFullname)
	ch.equal("serviceAccountName", chartFullname, pod.ServiceAccountName)
	ch.expectf(pod.AutomountServiceAccountToken != nil && *pod.AutomountServiceAccountToken == c.policyReport,
		"automountServiceAccountToken: want %t", c.policyReport)
	roleName := chartNamespace + "-" + chartFullname + "-policyreport"
	var role k8sClusterRole
	found, err = r.decode("ClusterRole", roleName, &role)
	ch.noError("ClusterRole", err)
	ch.equal("ClusterRole present", c.policyReport, found)
	var binding k8sClusterRoleBinding
	bound, err := r.decode("ClusterRoleBinding", roleName, &binding)
	ch.noError("ClusterRoleBinding", err)
	ch.equal("ClusterRoleBinding present", c.policyReport, bound)
	ch.equal("ClusterRole count", len(r["ClusterRole"]), len(r["ClusterRoleBinding"]))
	if found {
		ch.equal("ClusterRole rules", policyReportRules, role.Rules)
	}
	if bound {
		ok := binding.RoleRef.Name == roleName && len(binding.Subjects) == 1 &&
			binding.Subjects[0].Name == chartFullname && binding.Subjects[0].Namespace == chartNamespace
		ch.expectf(ok, "ClusterRoleBinding: got %+v", binding)
	}

	if c.management {
		ch.equal("management.listen_address", "::", dig(sidekick, "management", "listen_address"))
	} else {
		ch.equal("management.listen_address", nil, dig(sidekick, "management", "listen_address"))
	}
}

// checkSelectors requires the Deployment to own its pods and every Service, ServiceMonitor and
// PodDisruptionBudget selector to pick those pods and nothing else the chart renders.
func (c *chartCase) checkSelectors(ch *checker, r chartRender, deploy *k8sDeployment) {
	podLabels := deploy.Spec.Template.Metadata.Labels
	selector := deploy.Spec.Selector.MatchLabels
	ch.equal("Deployment selector", map[string]string{"app.kubernetes.io/name": "falcosidekick", "app.kubernetes.io/instance": chartRelease}, selector)
	ch.expectf(selects(selector, podLabels), "Deployment selector %v: does not select its pods %v", selector, podLabels)

	var testPod k8sPod
	_, err := r.decode("Pod", chartFullname+"-test", &testPod)
	ch.noError("test Pod", err)
	ch.expectf(!selects(selector, testPod.Metadata.Labels), "Deployment selector: selects the test pod")
	var ingest k8sService
	for name := range r["Service"] {
		var svc k8sService
		_, err := r.decode("Service", name, &svc)
		ch.noError("Service "+name, err)
		ch.equal("Service "+name+" selector", selector, svc.Spec.Selector)
		ch.expectf(!selects(svc.Spec.Selector, testPod.Metadata.Labels), "Service %s: selects the test pod", name)
		if name == chartFullname {
			ingest = svc
		}
	}
	if c.serviceMonitor {
		var sm k8sServiceMonitor
		_, err := r.decode("ServiceMonitor", chartFullname, &sm)
		ch.noError("ServiceMonitor", err)
		ch.expectf(selects(sm.Spec.Selector.MatchLabels, ingest.Metadata.Labels), "ServiceMonitor: does not select the ingest Service")
		for name := range r["Service"] {
			var svc k8sService
			_, _ = r.decode("Service", name, &svc)
			ch.expectf(name == chartFullname || !selects(sm.Spec.Selector.MatchLabels, svc.Metadata.Labels),
				"ServiceMonitor: selects Service %s", name)
		}
	}
}

func (c *chartCase) checkUI(ch *checker, sidekick, outputs map[string]any) {
	ch.equal("ui.enabled", c.ui, dig(sidekick, "ui", "enabled"))
	configured, _ := dig(outputs, "outputs").(map[string]any)
	_, inmemory := configured["inmemory"]
	ch.equal("inmemory output", c.ui, inmemory)
	if c.ui {
		ch.equal("ui.event_source", "inmemory", dig(sidekick, "ui", "event_source"))
		ch.equal("api.allow_writes", false, dig(sidekick, "api", "allow_writes"))
	} else {
		ch.equal("api.allow_writes", nil, dig(sidekick, "api", "allow_writes"))
	}
}

func (c *chartCase) checkTestPod(ch *checker, r chartRender, tls bool) {
	var pod k8sPod
	found, err := r.decode("Pod", chartFullname+"-test", &pod)
	if !found || err != nil {
		ch.expectf(false, "test Pod: found=%t err=%v", found, err)
		return
	}
	ch.equal("test Pod hook", "test", pod.Metadata.Annotations["helm.sh/hook"])
	ch.equal("test Pod restartPolicy", "Never", pod.Spec.RestartPolicy)
	ch.expectf(pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken, "test Pod: want no token")
	if len(pod.Spec.Containers) != 1 {
		ch.expectf(false, "test Pod: want one container")
		return
	}
	container := &pod.Spec.Containers[0]
	ch.equal("test Pod command", []string{"curl"}, container.Command)
	url := fmt.Sprintf("%s://%s.%s.svc:2801/readyz", urlScheme(tls), chartFullname, chartNamespace)
	ch.expectf(len(container.Args) > 0 && container.Args[len(container.Args)-1] == url, "test Pod: want a call to %s, got %v", url, container.Args)
	ch.equal("test Pod --insecure", tls, slices.Contains(container.Args, "--insecure"))
	ch.expectf(isTrue(container.SecurityContext.ReadOnlyRootFilesystem) && isTrue(container.SecurityContext.RunAsNonRoot),
		"test Pod: want the container security context")
}

// TestChartRendersEveryCombination renders the cartesian product of the chart axes, checks the
// invariants of each valid combination, runs its files through the process's loaders, and checks
// the refusal of each invalid one.
func TestChartRendersEveryCombination(t *testing.T) {
	helm := requireHelm(t)
	appVersion := chartAppVersion(t)
	fixture := newRuntimeFixture(t)
	cases := chartCases()
	require.Len(t, cases, 2*2*3*2*4*2*2*2*2*2)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	problems := make([][]string, len(cases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for i := range jobs {
				problems[i] = runChartCase(ctx, helm, &cases[i], appVersion, fixture)
			}
		})
	}
	for i := range cases {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	const maxReported = 20
	failed, invalid := 0, 0
	for i := range cases {
		c := &cases[i]
		if len(c.expectedErrors()) > 0 {
			invalid++
		}
		if len(problems[i]) == 0 {
			continue
		}
		failed++
		if failed <= maxReported {
			t.Errorf("%s:\n  %s", c, strings.Join(problems[i], "\n  "))
		}
	}
	if failed > maxReported {
		t.Errorf("%d more failing combinations", failed-maxReported)
	}
	// UI with slim: 1/4 of the cases; sqlite with 2 replicas: 1/6; both: 1/24.
	assert.Equal(t, len(cases)/4+len(cases)/6-len(cases)/24, invalid, "refused combinations")
	t.Logf("%d combinations, %d valid, %d refused, %d failing, in %s",
		len(cases), len(cases)-invalid, invalid, failed, time.Since(start).Round(time.Millisecond))
}

func runChartCase(ctx context.Context, helm string, c *chartCase, appVersion string, fixture *runtimeFixture) []string {
	r, err := renderChart(ctx, helm, c.values())
	wantErrs := c.expectedErrors()
	if len(wantErrs) == 0 {
		if err != nil {
			return []string{fmt.Sprintf("render: %v", err)}
		}
		return c.check(r, appVersion, fixture)
	}
	if err == nil {
		return []string{fmt.Sprintf("render: want failure with %q, got success", wantErrs)}
	}
	var problems []string
	for _, want := range wantErrs {
		if !strings.Contains(err.Error(), want) {
			problems = append(problems, fmt.Sprintf("render error: want %q, got %v", want, err))
		}
	}
	return problems
}

func chartBase() map[string]any {
	return map[string]any{"outputs": map[string]any{"webhook": map[string]any{"host": chartWebhookHost}}}
}

// with returns the base values with value set at a dotted path.
func with(values map[string]any, dotted string, value any) map[string]any {
	keys := strings.Split(dotted, ".")
	cur := values
	for _, key := range keys[:len(keys)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[key] = next
		}
		cur = next
	}
	cur[keys[len(keys)-1]] = value
	return values
}

func postgresValues() map[string]any {
	values := chartBase()
	with(values, "database.backend", dbPostgres)
	with(values, "database.postgres.passwordSecret.name", chartPGSecret)
	with(values, "config.database.postgres", map[string]any{"host": "pg", "database": "fsk", "user": "fsk"})
	return values
}

// TestChartRefusals covers every value the chart refuses: each message names the key, and no
// message repeats the value, which can be a credential.
func TestChartRefusals(t *testing.T) {
	helm := requireHelm(t)
	secret := func(path string) map[string]any { return with(chartBase(), path, chartSentinel) }
	header := func(output, field string) map[string]any {
		return with(chartBase(), "outputs."+output+"."+field, map[string]any{"Authorization": map[string]any{"secrets": []any{chartSentinel}}})
	}
	tlsOn := func() map[string]any { return with(chartBase(), "config.tls.enabled", true) }
	for _, tc := range []struct {
		values map[string]any
		name   string
		want   []string
	}{
		{secret("outputs.webhook.password"), "string secret",
			[]string{"outputs.webhook.password: credentials cannot be written in values", "set password_file"}},
		{secret("outputs.webhook.Bearer_Token"), "string secret spelled with capitals",
			[]string{"outputs.webhook.Bearer_Token: credentials cannot be written in values", "set bearer_token_file"}},
		{secret("outputs.kafka.auth.password"), "nested string secret",
			[]string{"outputs.kafka.auth.password: credentials cannot be written in values", "set password_file"}},
		{secret("outputs.datadog.api_key"), "required string secret", []string{"outputs.datadog.api_key: credentials cannot be written"}},
		{secret("outputs.slack.secret_endpoint"), "secret endpoint", []string{"outputs.slack.secret_endpoint: credentials cannot be written"}},
		{header("webhook", "headers"), "header secret",
			[]string{"outputs.webhook.headers.Authorization.secrets: credentials cannot be written in values", "list their paths in files"}},
		{header("loki", "query_params"), "query secret", []string{"outputs.loki.query_params.Authorization.secrets: credentials cannot be written"}},
		{header("otlp", "logs.headers"), "nested header secret",
			[]string{"outputs.otlp.logs.headers.Authorization.secrets: credentials cannot be written"}},
		{with(chartBase(), "outputs.webhook.headers", map[string]any{"X-Token": chartSentinel}), "header written as a string",
			[]string{"outputs.webhook.headers.X-Token: must be a map of values, secrets and files"}},
		{with(postgresValues(), "config.database.postgres.password", chartSentinel), "postgres password",
			[]string{"config.database.postgres.password: credentials cannot be written in values: set database.postgres.passwordSecret"}},
		{with(chartBase(), "extraEnv", []any{map[string]any{"name": "FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD", "value": chartSentinel}}),
			"postgres password in extraEnv", []string{"extraEnv FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD: credentials cannot be written"}},

		{tlsOn(), "TLS without certificate", []string{"config.tls.enabled needs tls.secretName, or both config.tls.cert_file and config.tls.key_file"}},
		{with(tlsOn(), "config.tls.cert_file", "/c"), "TLS with a certificate and no key", []string{"config.tls.enabled needs tls.secretName"}},
		{with(chartBase(), "tls.secretName", chartTLSSecret), "TLS Secret without TLS",
			[]string{"tls.secretName is set but config.tls.enabled is not true"}},
		{with(with(with(tlsOn(), "config.tls.mutual_tls", true), "config.tls.cert_file", "/c"), "config.tls.key_file", "/k"),
			"mutual TLS without CA", []string{"config.tls.mutual_tls needs a CA"}},
		{with(chartBase(), "config.tls.mutual_tls", true), "mutual TLS without TLS", []string{"config.tls.mutual_tls: needs config.tls.enabled"}},
		{with(chartBase(), "config.tls.cert_file", "/c"), "certificate without TLS", []string{"config.tls.cert_file: needs config.tls.enabled"}},
		{with(chartBase(), "config.tls.key_file", "/k"), "key without TLS", []string{"config.tls.key_file: needs config.tls.enabled"}},
		{with(chartBase(), "config.tls.ca_file", "/ca"), "CA without TLS", []string{"config.tls.ca_file: needs config.tls.enabled"}},
		{with(with(chartBase(), "config.tls.enabled", false), "config.tls.cert_file", "/c"), "certificate with TLS off",
			[]string{"config.tls.cert_file: needs config.tls.enabled"}},

		{with(postgresValues(), "config.database.postgres", map[string]any{}), "postgres without connection", []string{
			"database.backend postgres needs config.database.postgres.host",
			"database.backend postgres needs config.database.postgres.database",
			"database.backend postgres needs config.database.postgres.user",
		}},
		{with(postgresValues(), "database.postgres.passwordSecret.name", ""), "postgres without password",
			[]string{"database.backend postgres needs a password"}},
		{with(postgresValues(), "config.database.postgres.password_file", "/etc/falcosidekick/secrets/pg/password"), "postgres with two passwords",
			[]string{"database.postgres.passwordSecret.name and config.database.postgres.password_file are both set"}},
		{with(postgresValues(), "database.postgres.passwordSecret.key", ""), "postgres Secret without key",
			[]string{"database.postgres.passwordSecret.key is required"}},

		{with(chartBase(), "config.database.backend", dbSQLite), "config.database.backend",
			[]string{`config.database.backend "sqlite" contradicts database.backend "inmemory"`}},
		{with(with(chartBase(), "database.backend", dbSQLite), "config.database.sqlite.path", "/tmp/x.db"), "config.database.sqlite.path",
			[]string{"config.database.sqlite.path contradicts the volume the chart mounts"}},
		{with(chartBase(), "config.ui.enabled", false), "config.ui.enabled", []string{"config.ui.enabled false contradicts ui.enabled true"}},
		{with(with(chartBase(), "management.service.enabled", true), "config.management.listen_address", "127.0.0.1"),
			"config.management.listen_address", []string{`config.management.listen_address "127.0.0.1" contradicts management.service.enabled`}},

		{with(chartBase(), "config.shutdown_delay", "soon"), "shutdown_delay not a duration", []string{`config.shutdown_delay "soon" is not a duration`}},
		{with(chartBase(), "config.shutdown_delay", "5"), "shutdown_delay without unit", []string{`config.shutdown_delay "5" is not a duration`}},
		{with(chartBase(), "config.shutdown_delay", "-5s"), "negative shutdown_delay", []string{`config.shutdown_delay "-5s" is not a duration`}},
		{with(chartBase(), "config.shutdown_delay", -1), "negative shutdown_delay in nanoseconds",
			[]string{"config.shutdown_delay -1 must not be negative"}},
		{with(chartBase(), "config.database.connect_timeout", "later"), "connect_timeout not a duration",
			[]string{`config.database.connect_timeout "later" is not a duration`}},

		{with(with(chartBase(), "rbac.policyReport", true), "serviceAccount.create", false), "policyReport without account",
			[]string{"rbac.policyReport with serviceAccount.create=false needs serviceAccount.name"}},
		{with(chartBase(), "extraOutputConfigMaps", []any{map[string]any{"key": "x.yaml"}}), "extra outputs without name",
			[]string{"extraOutputConfigMaps[0].name is required"}},
		{with(chartBase(), "extraOutputConfigMaps", []any{map[string]any{"name": "a"}, map[string]any{"name": "a"}}), "extra outputs twice",
			[]string{`extraOutputConfigMaps: "a" is listed twice`}},
		{with(with(chartBase(), "podDisruptionBudget.enabled", true), "podDisruptionBudget.maxUnavailable", ""), "PodDisruptionBudget without bound",
			[]string{"podDisruptionBudget needs minAvailable or maxUnavailable"}},
		{with(chartBase(), "image.variant", "tiny"), "unsupported variant", []string{`image.variant "tiny" is not supported`}},
		{with(chartBase(), "database.backend", "mysql"), "unsupported backend", []string{`database.backend "mysql" is not supported`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderChart(t.Context(), helm, tc.values)
			require.Error(t, err)
			for _, want := range tc.want {
				assert.ErrorContains(t, err, want)
			}
			assert.NotContains(t, err.Error(), chartSentinel, "the message repeats the value")
		})
	}

	t.Run("every variable the chart reads is refused in extraEnv", func(t *testing.T) {
		names := []string{
			"FALCOSIDEKICK_LISTEN_PORT", "FALCOSIDEKICK_MANAGEMENT_LISTEN_PORT", "FALCOSIDEKICK_MANAGEMENT_LISTEN_ADDRESS",
			"FALCOSIDEKICK_SHUTDOWN_DELAY", "FALCOSIDEKICK_TLS_ENABLED", "FALCOSIDEKICK_TLS_MUTUAL_TLS",
			"FALCOSIDEKICK_TLS_CERT_FILE", "FALCOSIDEKICK_TLS_KEY_FILE", "FALCOSIDEKICK_TLS_CA_FILE",
			"FALCOSIDEKICK_DATABASE_BACKEND", "FALCOSIDEKICK_DATABASE_CONNECT_TIMEOUT", "FALCOSIDEKICK_DATABASE_SQLITE_PATH",
			"FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD_FILE", "FALCOSIDEKICK_UI_ENABLED", "FALCOSIDEKICK_UI_EVENT_SOURCE",
			"FALCOSIDEKICK_API_SECRET_DIRS",
		}
		env := make([]any, len(names))
		for i, name := range names {
			env[i] = map[string]any{"name": name, "value": chartSentinel}
		}
		_, err := renderChart(t.Context(), helm, with(chartBase(), "extraEnv", env))
		require.Error(t, err)
		for _, name := range names {
			assert.ErrorContains(t, err, "extraEnv "+name+": the chart reads this setting from config")
		}
		assert.NotContains(t, err.Error(), chartSentinel)
	})
}

// TestChartOverrides covers the values the combinations keep at their defaults.
func TestChartOverrides(t *testing.T) {
	helm := requireHelm(t)
	render := func(t *testing.T, values map[string]any) chartRender {
		t.Helper()
		r, err := renderChart(t.Context(), helm, values)
		require.NoError(t, err)
		return r
	}
	deployment := func(t *testing.T, r chartRender) k8sDeployment {
		t.Helper()
		var d k8sDeployment
		found, err := r.decode("Deployment", chartFullname, &d)
		require.NoError(t, err)
		require.True(t, found)
		return d
	}
	pdb := func(t *testing.T, values map[string]any) k8sPDB {
		t.Helper()
		var p k8sPDB
		found, err := render(t, with(values, "podDisruptionBudget.enabled", true)).decode("PodDisruptionBudget", chartFullname, &p)
		require.NoError(t, err)
		require.True(t, found)
		return p
	}

	t.Run("UI keeps allow_writes and an inmemory output set by the user", func(t *testing.T) {
		values := with(chartBase(), "config.api.allow_writes", true)
		with(values, "outputs.inmemory", map[string]any{"capacity": 50})
		r := render(t, values)
		sidekick, err := r.configFile("sidekick.yaml")
		require.NoError(t, err)
		outputs, err := r.configFile("outputs.yaml")
		require.NoError(t, err)
		assert.Equal(t, true, dig(sidekick, "api", "allow_writes"))
		assert.Equal(t, map[string]any{"capacity": 50}, dig(outputs, "outputs", "inmemory"))
	})

	t.Run("credentials read from files are accepted", func(t *testing.T) {
		values := with(chartBase(), "outputs.webhook.password_file", "/etc/falcosidekick/secrets/hook/password")
		with(values, "outputs.webhook.headers", map[string]any{"Authorization": map[string]any{
			"values": []any{"public"}, "files": []any{"/etc/falcosidekick/secrets/hook/token"},
		}})
		with(values, "outputs.kafka", map[string]any{
			"brokers": []any{"kafka:9092"}, "auth": map[string]any{"password_file": "/etc/falcosidekick/secrets/hook/kafka"},
		})
		with(values, "secrets", []any{"hook"})
		with(values, "extraEnv", []any{map[string]any{"name": "FALCOSIDEKICK_LOG_LEVEL", "value": "debug"}})
		r := render(t, values)
		outputs, err := r.configFile("outputs.yaml")
		require.NoError(t, err)
		assert.Equal(t, "/etc/falcosidekick/secrets/hook/password", dig(outputs, "outputs", "webhook", "password_file"))
	})

	t.Run("settings equal to what the chart sets are accepted", func(t *testing.T) {
		values := with(chartBase(), "config.database.backend", "inmemory")
		with(values, "config.ui.enabled", true)
		with(values, "management.service.enabled", true)
		with(values, "config.management.listen_address", "::")
		render(t, values)
		sqlite := with(chartBase(), "database.backend", dbSQLite)
		with(sqlite, "config.database.sqlite.path", "/var/lib/falcosidekick/sidekick.db")
		render(t, sqlite)
		withoutService := with(chartBase(), "config.management.listen_address", "0.0.0.0")
		sidekick, err := render(t, withoutService).configFile("sidekick.yaml")
		require.NoError(t, err)
		assert.Equal(t, "0.0.0.0", dig(sidekick, "management", "listen_address"), "without the Service the address is the user's")
	})

	t.Run("TLS from user files and postgres password from a file", func(t *testing.T) {
		values := postgresValues()
		with(values, "database.postgres.passwordSecret.name", "")
		with(values, "config.database.postgres.password_file", "/etc/falcosidekick/secrets/pg/password")
		with(values, "config.tls", map[string]any{"enabled": true, "mutual_tls": true, "cert_file": "/c", "key_file": "/k", "ca_file": "/ca"})
		r := render(t, values)
		sidekick, err := r.configFile("sidekick.yaml")
		require.NoError(t, err)
		assert.Equal(t, "/ca", dig(sidekick, "tls", "ca_file"))
		assert.Equal(t, "/etc/falcosidekick/secrets/pg/password", dig(sidekick, "database", "postgres", "password_file"))
		for _, v := range deployment(t, r).Spec.Template.Spec.Volumes {
			assert.Nil(t, v.Secret, "no Secret is mounted by the chart: %s", v.Name)
		}
	})

	t.Run("terminationGracePeriodSeconds follows shutdown_delay", func(t *testing.T) {
		for _, tc := range []struct {
			delay any
			want  int64
		}{
			{"0", 15}, {"500ms", 16}, {".5s", 16}, {"1.s", 16}, {"+2s", 17}, {"1m30s", 105}, {"1h", 3615},
			{"1h0m0.5s", 3616}, {"300us", 16}, {"300µs", 16}, {"300μs", 16}, {"1000ns", 16}, {"30s", 45},
			{int64(2e9), 17}, {int64(0), 15},
		} {
			pod := deployment(t, render(t, with(chartBase(), "config.shutdown_delay", tc.delay))).Spec.Template.Spec
			require.NotNil(t, pod.TerminationGracePeriodSeconds, "%v", tc.delay)
			assert.Equal(t, tc.want, *pod.TerminationGracePeriodSeconds, "shutdown_delay %v", tc.delay)
		}
	})

	t.Run("startupProbe budget covers connect_timeout", func(t *testing.T) {
		for _, tc := range []struct {
			values map[string]any
			want   int
		}{
			{chartBase(), 12},
			{with(chartBase(), "config.database.connect_timeout", "2m"), 30},
			{with(chartBase(), "config.database.connect_timeout", "1m1s"), 19},
			{with(chartBase(), "config.database.connect_timeout", "500ms"), 7},
			{with(chartBase(), "probes.startup.periodSeconds", 2), 30},
			{with(chartBase(), "probes.startup.failureThreshold", 4), 4},
		} {
			probe := deployment(t, render(t, tc.values)).Spec.Template.Spec.Containers[0].StartupProbe
			require.NotNil(t, probe)
			assert.Equal(t, tc.want, probe.FailureThreshold, "%v", tc.values)
		}
		values := with(chartBase(), "probes.liveness", map[string]any{"periodSeconds": 7, "timeoutSeconds": 2, "failureThreshold": 9})
		with(values, "probes.readiness", map[string]any{"periodSeconds": 4, "timeoutSeconds": 1, "failureThreshold": 2})
		container := deployment(t, render(t, values)).Spec.Template.Spec.Containers[0]
		timings := func(p *k8sProbe) []int { return []int{p.PeriodSeconds, p.TimeoutSeconds, p.FailureThreshold} }
		assert.Equal(t, []int{7, 2, 9}, timings(container.LivenessProbe))
		assert.Equal(t, []int{4, 1, 2}, timings(container.ReadinessProbe))
	})

	t.Run("checksum follows sidekick.yaml only", func(t *testing.T) {
		annotation := func(values map[string]any) string {
			return deployment(t, render(t, values)).Spec.Template.Metadata.Annotations["checksum/config"]
		}
		first := annotation(chartBase())
		assert.Equal(t, first, annotation(with(chartBase(), "outputs.webhook.host", "http://other:8080")))
		assert.NotEqual(t, first, annotation(with(chartBase(), "config.log_level", "debug")))
	})

	t.Run("image registry, digest, tag and variant", func(t *testing.T) {
		image := func(values map[string]any) string {
			return deployment(t, render(t, values)).Spec.Template.Spec.Containers[0].Image
		}
		values := with(chartBase(), "image", map[string]any{"tag": "ignored", "digest": "sha256:0123", "variant": variantSlim})
		with(values, "ui.enabled", false)
		assert.Equal(t, "docker.io/falcosecurity/falcosidekick@sha256:0123", image(values))
		tagged := func() map[string]any { return with(chartBase(), "image.tag", "9.9") }
		assert.Equal(t, "registry.example/falcosecurity/falcosidekick:9.9", image(with(tagged(), "image.registry", "registry.example")))
		assert.Equal(t, "mirror/sidekick:9.9", image(with(with(tagged(), "image.registry", ""), "image.repository", "mirror/sidekick")))
	})

	t.Run("pod scheduling and Service families", func(t *testing.T) {
		values := with(chartBase(), "priorityClassName", "high")
		with(values, "resources", map[string]any{"limits": map[string]any{"memory": "128Mi"}})
		with(values, "service.ipFamilyPolicy", "PreferDualStack")
		with(values, "service.ipFamilies", []any{"IPv6", "IPv4"})
		with(values, "management.service", map[string]any{"enabled": true, "ipFamilyPolicy": "SingleStack", "ipFamilies": []any{"IPv6"}})
		r := render(t, values)
		pod := deployment(t, r).Spec.Template.Spec
		assert.Equal(t, "high", pod.PriorityClassName)
		assert.Equal(t, map[string]string{"memory": "128Mi"}, pod.Containers[0].Resources.Limits)
		var svc, mgmt k8sService
		_, err := r.decode("Service", chartFullname, &svc)
		require.NoError(t, err)
		_, err = r.decode("Service", chartFullname+"-management", &mgmt)
		require.NoError(t, err)
		assert.Equal(t, "PreferDualStack", svc.Spec.IPFamilyPolicy)
		assert.Equal(t, []string{"IPv6", "IPv4"}, svc.Spec.IPFamilies)
		assert.Equal(t, "SingleStack", mgmt.Spec.IPFamilyPolicy)
		assert.Equal(t, []string{"IPv6"}, mgmt.Spec.IPFamilies)
	})

	t.Run("existing claim is used without creating one", func(t *testing.T) {
		values := with(chartBase(), "database.backend", dbSQLite)
		with(values, "database.sqlite.persistence.existingClaim", "mine")
		r := render(t, values)
		assert.Empty(t, r["PersistentVolumeClaim"])
		claims := []string{}
		for _, v := range deployment(t, r).Spec.Template.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				claims = append(claims, v.PersistentVolumeClaim.ClaimName)
			}
		}
		assert.Equal(t, []string{"mine"}, claims)
	})

	t.Run("claim kept unless keep is false", func(t *testing.T) {
		values := with(chartBase(), "database.backend", dbSQLite)
		with(values, "database.sqlite.persistence", map[string]any{"keep": false, "annotations": map[string]any{"a": "b"}})
		var pvc k8sObject
		found, err := render(t, values).decode("PersistentVolumeClaim", chartFullname+"-data", &pvc)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, map[string]string{"a": "b"}, pvc.Metadata.Annotations)
	})

	t.Run("PodDisruptionBudget", func(t *testing.T) {
		assert.NotContains(t, render(t, chartBase())["PodDisruptionBudget"], chartFullname)
		def := pdb(t, chartBase())
		assert.Equal(t, 1, def.Spec.MaxUnavailable, "one replica can be drained by default")
		assert.Nil(t, def.Spec.MinAvailable)
		zero := pdb(t, with(chartBase(), "podDisruptionBudget.maxUnavailable", 0))
		assert.Equal(t, 0, zero.Spec.MaxUnavailable)
		assert.Nil(t, zero.Spec.MinAvailable)
		percent := pdb(t, with(chartBase(), "podDisruptionBudget.maxUnavailable", "50%"))
		assert.Equal(t, "50%", percent.Spec.MaxUnavailable)
		minimum := pdb(t, with(chartBase(), "podDisruptionBudget.minAvailable", 0))
		assert.Equal(t, 0, minimum.Spec.MinAvailable)
		assert.Nil(t, minimum.Spec.MaxUnavailable, "minAvailable replaces maxUnavailable")
		assert.Equal(t, map[string]string{"app.kubernetes.io/name": "falcosidekick", "app.kubernetes.io/instance": chartRelease},
			def.Spec.Selector.MatchLabels)
	})

	t.Run("names stay within 63 characters", func(t *testing.T) {
		long := strings.Repeat("n", 63)
		values := with(chartBase(), "fullnameOverride", long)
		with(values, "management.service.enabled", true)
		with(values, "database.backend", dbSQLite)
		with(values, "rbac.policyReport", true)
		r := render(t, values)
		for kind, objs := range r {
			for name := range objs {
				limit := 63
				if kind == "ClusterRole" || kind == "ClusterRoleBinding" {
					limit = 253
				}
				assert.LessOrEqual(t, len(name), limit, "%s %s", kind, name)
				assert.False(t, strings.HasSuffix(name, "-"), "%s %s", kind, name)
			}
		}
		short := long[:63-len("-management")]
		assert.Contains(t, r["Service"], short+"-management")
		assert.Contains(t, r["PersistentVolumeClaim"], long[:63-len("-data")]+"-data")
		assert.Contains(t, r["Pod"], long[:63-len("-test")]+"-test")
		assert.Contains(t, r["ClusterRole"], chartNamespace+"-"+long+"-policyreport", "not truncated, so two releases never share it")
		var d k8sDeployment
		found, err := r.decode("Deployment", long, &d)
		require.NoError(t, err)
		require.True(t, found)
		claims := []string{}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				claims = append(claims, v.PersistentVolumeClaim.ClaimName)
			}
		}
		assert.Equal(t, []string{long[:63-len("-data")] + "-data"}, claims)
	})

	t.Run("service account token", func(t *testing.T) {
		automount := func(values map[string]any) bool {
			return isTrue(deployment(t, render(t, values)).Spec.Template.Spec.AutomountServiceAccountToken)
		}
		assert.False(t, automount(chartBase()))
		assert.True(t, automount(with(chartBase(), "outputs.policyreport", map[string]any{})), "the output needs the token with user-managed RBAC")
		assert.True(t, automount(with(chartBase(), "rbac.policyReport", true)))
		values := with(with(chartBase(), "rbac.policyReport", true), "serviceAccount", map[string]any{"create": false, "name": "mine"})
		r := render(t, values)
		assert.Empty(t, r["ServiceAccount"])
		var binding k8sClusterRoleBinding
		_, err := r.decode("ClusterRoleBinding", chartNamespace+"-"+chartFullname+"-policyreport", &binding)
		require.NoError(t, err)
		require.Len(t, binding.Subjects, 1)
		assert.Equal(t, "mine", binding.Subjects[0].Name)
	})

	t.Run("extra output ConfigMaps follow the chart's file in list order", func(t *testing.T) {
		values := with(chartBase(), "extraOutputConfigMaps", []any{map[string]any{"name": "b", "key": "slack.yaml"}, map[string]any{"name": "a"}})
		container := deployment(t, render(t, values)).Spec.Template.Spec.Containers[0]
		assert.Equal(t, []string{
			"-c", "/etc/falcosidekick/config/sidekick.yaml", "-o", "/etc/falcosidekick/config/outputs.yaml",
			"-o", "/etc/falcosidekick/outputs/b/slack.yaml", "-o", "/etc/falcosidekick/outputs/a/outputs.yaml",
		}, container.Args)
	})

	t.Run("test pod can be turned off and uses its image", func(t *testing.T) {
		assert.Empty(t, render(t, with(chartBase(), "test.enabled", false))["Pod"])
		var pod k8sPod
		found, err := render(t, with(chartBase(), "test.image.registry", "")).decode("Pod", chartFullname+"-test", &pod)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, "curlimages/curl:8.11.1", pod.Spec.Containers[0].Image)
	})
}

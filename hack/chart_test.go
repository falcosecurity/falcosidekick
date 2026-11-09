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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

const (
	chartDir           = "../chart/falcosidekick"
	chartRelease       = "fsk"
	chartFullname      = "fsk-falcosidekick"
	chartNamespace     = "falco"
	chartSkipNoHelmEnv = "FSK_CHART_TEST_SKIP_NO_HELM"
	chartTLSSecret     = "fsk-tls"
	chartPGSecret      = "pg-auth"
	chartUserSecretDir = "/custom/dir"
	chartWebhookHost   = "http://receiver.falco.svc:8080"

	errSlimUI         = "image.variant slim has no web UI"
	errSQLiteReplicas = "database.backend sqlite supports replicaCount 1 only"

	dbSQLite   = "sqlite"
	dbPostgres = "postgres"
	tlsOff     = "off"
	tlsMutual  = "mutual"

	variantSlim = "slim"
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
}

func (c *chartCase) String() string {
	return fmt.Sprintf("ui=%t variant=%q database=%s replicas=%d tls=%s management=%t serviceMonitor=%t policyReport=%t secrets=%v",
		c.ui, c.variant, c.database, c.replicas, c.tls, c.management, c.serviceMonitor, c.policyReport, c.secrets)
}

// chartCases is the cartesian product of every axis.
func chartCases() []chartCase {
	cases := make([]chartCase, 0, 1152)
	for _, ui := range []bool{true, false} {
		for _, variant := range []string{"", variantSlim} {
			for _, database := range []string{"inmemory", dbSQLite, dbPostgres} {
				for _, replicas := range []int{1, 2} {
					for _, tls := range []string{tlsOff, "on", tlsMutual} {
						for _, management := range []bool{true, false} {
							for _, serviceMonitor := range []bool{true, false} {
								for _, policyReport := range []bool{true, false} {
									for _, secrets := range [][]string{nil, {"a", "b"}} {
										cases = append(cases, chartCase{
											ui: ui, variant: variant, database: database, replicas: replicas, tls: tls,
											management: management, serviceMonitor: serviceMonitor, policyReport: policyReport,
											secrets: secrets,
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
	config := map[string]any{
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
		"config":         config,
		"outputs":        map[string]any{"webhook": map[string]any{"host": chartWebhookHost, "endpoint": "/falco"}},
	}
	if c.tls != tlsOff {
		config["tls"] = map[string]any{"enabled": true, "mutual_tls": c.tls == tlsMutual}
		values["tls"] = map[string]any{"secretName": chartTLSSecret}
	}
	if c.database == dbPostgres {
		config["database"] = map[string]any{"postgres": map[string]any{"host": "postgres.falco.svc", "user": "falcosidekick"}}
		values["database"].(map[string]any)["postgres"] = map[string]any{"passwordSecret": map[string]any{"name": chartPGSecret}}
	}
	return values
}

type k8sObject struct {
	Metadata struct {
		Annotations map[string]string `yaml:"annotations"`
		Labels      map[string]string `yaml:"labels"`
		Name        string            `yaml:"name"`
	} `yaml:"metadata"`
	Kind string `yaml:"kind"`
}

type k8sDeployment struct {
	Spec struct {
		Strategy struct {
			Type string `yaml:"type"`
		} `yaml:"strategy"`
		Template struct {
			Metadata struct {
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
			Spec k8sPodSpec `yaml:"spec"`
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
	LivenessProbe  *k8sProbe `yaml:"livenessProbe"`
	ReadinessProbe *k8sProbe `yaml:"readinessProbe"`
	Name           string    `yaml:"name"`
	Image          string    `yaml:"image"`
	Args           []string  `yaml:"args"`
	Ports          []struct {
		Name          string `yaml:"name"`
		Protocol      string `yaml:"protocol"`
		ContainerPort int    `yaml:"containerPort"`
	} `yaml:"ports"`
	VolumeMounts []struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

type k8sProbe struct {
	HTTPGet struct {
		Path   string `yaml:"path"`
		Scheme string `yaml:"scheme"`
		Port   int    `yaml:"port"`
	} `yaml:"httpGet"`
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

type k8sService struct {
	Spec struct {
		Ports []struct {
			Name       string `yaml:"name"`
			TargetPort string `yaml:"targetPort"`
			Port       int    `yaml:"port"`
		} `yaml:"ports"`
	} `yaml:"spec"`
}

type k8sServiceMonitor struct {
	Spec struct {
		Selector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"selector"`
		Endpoints []struct {
			Port   string `yaml:"port"`
			Path   string `yaml:"path"`
			Scheme string `yaml:"scheme"`
		} `yaml:"endpoints"`
	} `yaml:"spec"`
}

type k8sClusterRole struct {
	Rules []struct {
		APIGroups []string `yaml:"apiGroups"`
		Resources []string `yaml:"resources"`
		Verbs     []string `yaml:"verbs"`
	} `yaml:"rules"`
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

func (r chartRender) configFile(file string) (map[string]any, error) {
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
	var out map[string]any
	err = yaml.Unmarshal([]byte(cm.Data[file]), &out)
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

func (c *chartCase) check(r chartRender, appVersion string) []string {
	ch := &checker{}
	sidekick, err := r.configFile("sidekick.yaml")
	ch.expectf(err == nil, "sidekick.yaml: %v", err)
	outputs, err := r.configFile("outputs.yaml")
	ch.expectf(err == nil, "outputs.yaml: %v", err)

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
	c.checkSecrets(ch, sidekick, pod, container)
	c.checkUserConfig(ch, sidekick, outputs)
	c.checkTLS(ch, sidekick, pod, container, tls)
	c.checkDatabase(ch, r, sidekick, &deploy, container)
	c.checkOptionalObjects(ch, r, sidekick, pod, tls)
	c.checkUI(ch, sidekick, outputs)

	ch.equal("replicas", c.replicas, deploy.Spec.Replicas)
	ch.equal("container name", "falcosidekick", container.Name)
	ch.equal("args", []string{"-c", "/etc/falcosidekick/config/sidekick.yaml", "-o", "/etc/falcosidekick/config/outputs.yaml"}, container.Args)
	wantImage := "falcosecurity/falcosidekick:" + appVersion
	if c.variant != "" {
		wantImage += "-" + c.variant
	}
	ch.equal("image", wantImage, container.Image)
	// shutdown_delay is the default 5s; the process then drains for up to 10s.
	grace := int64(-1)
	if pod.TerminationGracePeriodSeconds != nil {
		grace = *pod.TerminationGracePeriodSeconds
	}
	ch.expectf(grace >= 5+10, "terminationGracePeriodSeconds: want >= 15, got %d", grace)

	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	_, err = r.decode("ConfigMap", chartFullname, &cm)
	ch.expectf(err == nil, "ConfigMap: %v", err)
	sum := sha256.Sum256([]byte(cm.Data["sidekick.yaml"]))
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

func (c *chartCase) checkProbesAndPorts(ch *checker, r chartRender, container *k8sContainer, tls bool) {
	scheme := "HTTP"
	if tls {
		scheme = "HTTPS"
	}
	for _, probe := range []struct {
		probe *k8sProbe
		name  string
		path  string
	}{{container.LivenessProbe, "livenessProbe", "/livez"}, {container.ReadinessProbe, "readinessProbe", "/readyz"}} {
		if probe.probe == nil {
			ch.expectf(false, "%s: missing", probe.name)
			continue
		}
		ch.equal(probe.name+" path", probe.path, probe.probe.HTTPGet.Path)
		ch.equal(probe.name+" port", 2801, probe.probe.HTTPGet.Port)
		ch.equal(probe.name+" scheme", scheme, probe.probe.HTTPGet.Scheme)
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

	var mgmt k8sService
	found, err = r.decode("Service", chartFullname+"-management", &mgmt)
	ch.expectf(err == nil, "management Service: %v", err)
	ch.equal("management Service present", c.management, found)
	if found {
		ch.expectf(len(mgmt.Spec.Ports) == 1 && mgmt.Spec.Ports[0].Port == 2802 && mgmt.Spec.Ports[0].TargetPort == portNames[2802],
			"management Service ports: want 2802 to container port %q, got %+v", portNames[2802], mgmt.Spec.Ports)
	}
}

func (c *chartCase) checkSecrets(ch *checker, sidekick map[string]any, pod *k8sPodSpec, container *k8sContainer) {
	wantDirs := make([]any, 0, 1+len(c.secrets))
	wantDirs = append(wantDirs, chartUserSecretDir)
	for _, name := range c.secrets {
		dir := "/etc/falcosidekick/secrets/" + name
		wantDirs = append(wantDirs, dir)
		mounted := false
		for _, m := range container.VolumeMounts {
			if m.MountPath != dir {
				continue
			}
			for _, v := range pod.Volumes {
				if v.Name == m.Name && v.Secret != nil && v.Secret.SecretName == name && m.ReadOnly {
					mounted = true
				}
			}
		}
		ch.expectf(mounted, "Secret %s: want mounted read-only at %s", name, dir)
	}
	ch.equal("api.secret_dirs", wantDirs, dig(sidekick, "api", "secret_dirs"))
}

func (c *chartCase) checkUserConfig(ch *checker, sidekick, outputs map[string]any) {
	ch.equal("log_format", "json", dig(sidekick, "log_format"))
	ch.equal("enricher.custom_tags", []any{"team-a"}, dig(sidekick, "enricher", "custom_tags"))
	ch.equal("outputs.webhook", map[string]any{"host": chartWebhookHost, "endpoint": "/falco"}, dig(outputs, "outputs", "webhook"))
}

func (c *chartCase) checkTLS(ch *checker, sidekick map[string]any, pod *k8sPodSpec, container *k8sContainer, tls bool) {
	mounted := false
	for _, m := range container.VolumeMounts {
		if m.MountPath != "/etc/falcosidekick/tls" {
			continue
		}
		for _, v := range pod.Volumes {
			if v.Name == m.Name && v.Secret != nil && v.Secret.SecretName == chartTLSSecret && m.ReadOnly {
				mounted = true
			}
		}
	}
	ch.equal("TLS Secret mounted", tls, mounted)
	if !tls {
		ch.equal("tls", nil, dig(sidekick, "tls"))
		return
	}
	ch.equal("tls.enabled", true, dig(sidekick, "tls", "enabled"))
	ch.equal("tls.cert_file", "/etc/falcosidekick/tls/tls.crt", dig(sidekick, "tls", "cert_file"))
	ch.equal("tls.key_file", "/etc/falcosidekick/tls/tls.key", dig(sidekick, "tls", "key_file"))
	ch.equal("tls.mutual_tls", c.tls == tlsMutual, dig(sidekick, "tls", "mutual_tls"))
	if c.tls == tlsMutual {
		ch.equal("tls.ca_file", "/etc/falcosidekick/tls/ca.crt", dig(sidekick, "tls", "ca_file"))
	} else {
		ch.equal("tls.ca_file", nil, dig(sidekick, "tls", "ca_file"))
	}
}

func (c *chartCase) checkDatabase(ch *checker, r chartRender, sidekick map[string]any, deploy *k8sDeployment, container *k8sContainer) {
	pod := &deploy.Spec.Template.Spec
	sqlite := c.database == dbSQLite
	ch.equal("database.backend", c.database, dig(sidekick, "database", "backend"))

	_, pvc := r["PersistentVolumeClaim"][chartFullname+"-data"]
	ch.equal("PersistentVolumeClaim present", sqlite, pvc)
	ch.equal("PersistentVolumeClaim count", map[bool]int{true: 1, false: 0}[sqlite], len(r["PersistentVolumeClaim"]))
	dataMounted := false
	for _, m := range container.VolumeMounts {
		if m.MountPath != "/var/lib/falcosidekick" {
			continue
		}
		for _, v := range pod.Volumes {
			if v.Name == m.Name && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == chartFullname+"-data" {
				dataMounted = true
			}
		}
	}
	ch.equal("data volume mounted", sqlite, dataMounted)
	if sqlite {
		ch.equal("database.sqlite.path", "/var/lib/falcosidekick/sidekick.db", dig(sidekick, "database", "sqlite", "path"))
		ch.equal("strategy", "Recreate", deploy.Spec.Strategy.Type)
	} else {
		ch.expectf(deploy.Spec.Strategy.Type != "Recreate", "strategy: want rolling update without sqlite")
	}

	pgMounted := false
	for _, v := range pod.Volumes {
		if v.Secret != nil && v.Secret.SecretName == chartPGSecret {
			pgMounted = true
		}
	}
	postgres := c.database == dbPostgres
	ch.equal("postgres password Secret mounted", postgres, pgMounted)
	if postgres {
		ch.equal("database.postgres.password_file", "/etc/falcosidekick/postgres/password", dig(sidekick, "database", "postgres", "password_file"))
		ch.equal("database.postgres.host", "postgres.falco.svc", dig(sidekick, "database", "postgres", "host"))
	}
}

func (c *chartCase) checkOptionalObjects(ch *checker, r chartRender, sidekick map[string]any, pod *k8sPodSpec, tls bool) {
	var sm k8sServiceMonitor
	found, err := r.decode("ServiceMonitor", chartFullname, &sm)
	ch.expectf(err == nil, "ServiceMonitor: %v", err)
	ch.equal("ServiceMonitor present", c.serviceMonitor, found)
	ch.equal("ServiceMonitor count", map[bool]int{true: 1, false: 0}[c.serviceMonitor], len(r["ServiceMonitor"]))
	if found {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		ok := len(sm.Spec.Endpoints) == 1 && sm.Spec.Endpoints[0].Path == "/metrics" &&
			sm.Spec.Endpoints[0].Scheme == scheme && sm.Spec.Endpoints[0].Port == scheme
		ch.expectf(ok, "ServiceMonitor endpoints: want /metrics over %s, got %+v", scheme, sm.Spec.Endpoints)
		ch.equal("ServiceMonitor component", "ingest", sm.Spec.Selector.MatchLabels["app.kubernetes.io/component"])
	}

	ch.expectf(len(r["ServiceAccount"][chartFullname]) > 0, "ServiceAccount %s: missing", chartFullname)
	ch.equal("serviceAccountName", chartFullname, pod.ServiceAccountName)
	ch.expectf(pod.AutomountServiceAccountToken != nil && *pod.AutomountServiceAccountToken == c.policyReport,
		"automountServiceAccountToken: want %t", c.policyReport)
	roleName := chartNamespace + "-" + chartFullname + "-policyreport"
	var role k8sClusterRole
	found, err = r.decode("ClusterRole", roleName, &role)
	ch.expectf(err == nil, "ClusterRole: %v", err)
	ch.equal("ClusterRole present", c.policyReport, found)
	var binding k8sClusterRoleBinding
	bound, err := r.decode("ClusterRoleBinding", roleName, &binding)
	ch.expectf(err == nil, "ClusterRoleBinding: %v", err)
	ch.equal("ClusterRoleBinding present", c.policyReport, bound)
	ch.equal("ClusterRole count", len(r["ClusterRole"]), len(r["ClusterRoleBinding"]))
	if found {
		ok := len(role.Rules) == 1 && slices.Equal(role.Rules[0].APIGroups, []string{"openreports.io"}) &&
			slices.Equal(role.Rules[0].Resources, []string{"reports", "clusterreports"}) &&
			slices.Equal(role.Rules[0].Verbs, []string{"get", "create", "update"})
		ch.expectf(ok, "ClusterRole rules: got %+v", role.Rules)
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

// TestChartRendersEveryCombination renders the cartesian product of the chart axes
// and checks the invariants of each valid combination and the refusal of each invalid one.
func TestChartRendersEveryCombination(t *testing.T) {
	helm := requireHelm(t)
	appVersion := chartAppVersion(t)
	cases := chartCases()
	require.Len(t, cases, 2*2*3*2*3*2*2*2*2)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	problems := make([][]string, len(cases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for i := range jobs {
				problems[i] = runChartCase(ctx, helm, &cases[i], appVersion)
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
	// UI with slim: 1152/4; sqlite with 2 replicas: 1152/6; both: 1152/24.
	assert.Equal(t, 288+192-48, invalid, "refused combinations")
	t.Logf("%d combinations, %d valid, %d refused, %d failing, in %s",
		len(cases), len(cases)-invalid, invalid, failed, time.Since(start).Round(time.Millisecond))
}

func runChartCase(ctx context.Context, helm string, c *chartCase, appVersion string) []string {
	r, err := renderChart(ctx, helm, c.values())
	wantErrs := c.expectedErrors()
	if len(wantErrs) == 0 {
		if err != nil {
			return []string{fmt.Sprintf("render: %v", err)}
		}
		return c.check(r, appVersion)
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

// TestChartOverrides covers the values the combinations keep at their defaults.
func TestChartOverrides(t *testing.T) {
	helm := requireHelm(t)
	base := func() map[string]any {
		return map[string]any{"outputs": map[string]any{"webhook": map[string]any{"host": chartWebhookHost}}}
	}
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

	t.Run("UI keeps allow_writes and an inmemory output set by the user", func(t *testing.T) {
		values := base()
		values["config"] = map[string]any{"api": map[string]any{"allow_writes": true}}
		values["outputs"].(map[string]any)["inmemory"] = map[string]any{"capacity": 50}
		r := render(t, values)
		sidekick, err := r.configFile("sidekick.yaml")
		require.NoError(t, err)
		outputs, err := r.configFile("outputs.yaml")
		require.NoError(t, err)
		assert.Equal(t, true, dig(sidekick, "api", "allow_writes"))
		assert.Equal(t, map[string]any{"capacity": 50}, dig(outputs, "outputs", "inmemory"))
	})

	t.Run("terminationGracePeriodSeconds follows shutdown_delay", func(t *testing.T) {
		for _, tc := range []struct {
			delay any
			min   int64
		}{
			{"0", 10}, {"500ms", 11}, {"1m30s", 100}, {"1h", 3610}, {int64(2e9), 12},
		} {
			values := base()
			values["config"] = map[string]any{"shutdown_delay": tc.delay}
			pod := deployment(t, render(t, values)).Spec.Template.Spec
			require.NotNil(t, pod.TerminationGracePeriodSeconds, "%v", tc.delay)
			assert.GreaterOrEqual(t, *pod.TerminationGracePeriodSeconds, tc.min, "shutdown_delay %v", tc.delay)
		}
		values := base()
		values["config"] = map[string]any{"shutdown_delay": "soon"}
		_, err := renderChart(t.Context(), helm, values)
		require.ErrorContains(t, err, `config.shutdown_delay "soon" is not a duration`)
	})

	t.Run("checksum follows sidekick.yaml only", func(t *testing.T) {
		annotation := func(values map[string]any) string {
			return deployment(t, render(t, values)).Spec.Template.Metadata.Annotations["checksum/config"]
		}
		first := annotation(base())
		changedOutputs := base()
		changedOutputs["outputs"].(map[string]any)["webhook"] = map[string]any{"host": "http://other:8080"}
		assert.Equal(t, first, annotation(changedOutputs))
		changedConfig := base()
		changedConfig["config"] = map[string]any{"log_level": "debug"}
		assert.NotEqual(t, first, annotation(changedConfig))
	})

	t.Run("digest replaces tag and variant", func(t *testing.T) {
		values := base()
		values["image"] = map[string]any{"tag": "ignored", "digest": "sha256:0123", "variant": variantSlim}
		values["ui"] = map[string]any{"enabled": false}
		pod := deployment(t, render(t, values)).Spec.Template.Spec
		assert.Equal(t, "falcosecurity/falcosidekick@sha256:0123", pod.Containers[0].Image)
	})

	t.Run("existing claim is used without creating one", func(t *testing.T) {
		values := base()
		values["database"] = map[string]any{"backend": dbSQLite, "sqlite": map[string]any{"persistence": map[string]any{"existingClaim": "mine"}}}
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

	t.Run("PodDisruptionBudget", func(t *testing.T) {
		values := base()
		values["podDisruptionBudget"] = map[string]any{"enabled": true}
		assert.Contains(t, render(t, values)["PodDisruptionBudget"], chartFullname)
		assert.NotContains(t, render(t, base())["PodDisruptionBudget"], chartFullname)
	})

	t.Run("unsupported variant and backend are refused", func(t *testing.T) {
		values := base()
		values["image"] = map[string]any{"variant": "tiny"}
		values["database"] = map[string]any{"backend": "mysql"}
		_, err := renderChart(t.Context(), helm, values)
		require.ErrorContains(t, err, `image.variant "tiny" is not supported`)
		require.ErrorContains(t, err, `database.backend "mysql" is not supported`)
	})
}

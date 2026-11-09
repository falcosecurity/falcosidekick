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

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// testMetricName is served on /metrics by every server startServer runs.
const testMetricName = "falcosidekick_test_gauge"

// startServer runs a server on free ports with cfg adjusted by tune and stops it at the end of the test.
func startServer(t *testing.T, tune func(*core.Config)) (srv *Server, port int) {
	t.Helper()
	cfg := testConfig(t)
	cfg.ListenPort, cfg.Management.ListenPort = freePort(t), freePort(t)
	tune(cfg)
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: testMetricName, Help: "Test gauge."}))
	srv, err = NewServer(&ServerConfig{
		Pipeline: p, Catalog: newTestCatalog(t), Logger: slog.New(slog.DiscardHandler), Config: cfg, Registry: registry,
	})
	require.NoError(t, err)
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv, cfg.ListenPort
}

func waitFor(t *testing.T, check func() bool) {
	t.Helper()
	require.Eventually(t, check, 5*time.Second, 20*time.Millisecond)
}

// Falco must reach Sidekick on IPv6-only and dual-stack clusters: the default listens on both.
func TestIngestionListensOnIPv4AndIPv6(t *testing.T) {
	l, err := new(net.ListenConfig).Listen(t.Context(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this host")
	}
	_ = l.Close()
	_, port := startServer(t, func(*core.Config) {})
	for _, host := range []string{"127.0.0.1", "::1"} {
		url := fmt.Sprintf("http://%s/livez", net.JoinHostPort(host, fmt.Sprint(port)))
		waitFor(t, func() bool {
			resp, err := http.Get(url) //nolint:noctx // test probe
			if err != nil {
				return false
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		})
	}
}

// With mutual TLS, kubelet probes and Prometheus present no client certificate: /livez, /readyz and
// /metrics answer them, while events and everything else need a certificate the CA signed.
func TestMutualTLSExemptsProbesAndMetrics(t *testing.T) {
	pki := newTestPKI(t)
	srv, port := startServer(t, func(c *core.Config) {
		c.TLS = &core.TLSConfig{Enabled: true, CertFile: pki.serverCert, KeyFile: pki.serverKey, MutualTLS: true, CACertFile: pki.caFile}
	})
	srv.SetReady(true)
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	anonymous := pki.client(t, false)
	authenticated := pki.client(t, true)

	waitFor(t, func() bool {
		resp, err := anonymous.Get(base + "/livez") //nolint:noctx // test probe
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	})
	for path, want := range map[string]int{"/livez": http.StatusOK, "/readyz": http.StatusOK, "/healthz": http.StatusUnauthorized} {
		resp, err := anonymous.Get(base + path) //nolint:noctx // test probe
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		assert.Equal(t, want, resp.StatusCode, path)
	}

	resp, err := anonymous.Get(base + "/metrics") //nolint:noctx // test scrape
	require.NoError(t, err)
	scrape, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a scrape needs no client certificate")
	assert.Contains(t, string(scrape), testMetricName)

	event := []byte(`{"rule":"r","priority":"Warning","output":"o","time":"2026-01-01T00:00:00Z","output_fields":{"a":"b"}}`)
	resp, err = anonymous.Post(base+"/", "application/json", bytes.NewReader(event)) //nolint:noctx // test request
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "events need a client certificate")

	resp, err = authenticated.Post(base+"/", "application/json", bytes.NewReader(event)) //nolint:noctx // test request
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

type testPKI struct {
	clientCert                    tls.Certificate
	pool                          *x509.CertPool
	caFile, serverCert, serverKey string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	issue := func(serial int64, usage x509.ExtKeyUsage, ips []net.IP) (certPEM, keyPEM []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}

	pki := &testPKI{pool: x509.NewCertPool()}
	pki.pool.AddCert(ca)
	pki.caFile = write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	serverCert, serverKey := issue(2, x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	pki.serverCert, pki.serverKey = write("server.crt", serverCert), write("server.key", serverKey)
	clientCert, clientKey := issue(3, x509.ExtKeyUsageClientAuth, nil)
	pki.clientCert, err = tls.X509KeyPair(clientCert, clientKey)
	require.NoError(t, err)
	return pki
}

func (p *testPKI) client(t *testing.T, withCertificate bool) *http.Client {
	t.Helper()
	cfg := &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}
	if withCertificate {
		cfg.Certificates = []tls.Certificate{p.clientCert}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

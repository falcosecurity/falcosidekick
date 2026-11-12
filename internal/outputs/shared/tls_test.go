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

package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func TestBuildTLSConfigDefaults(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSClientConfig{})
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Nil(t, cfg.RootCAs)
	assert.Empty(t, cfg.Certificates)
}

func TestBuildTLSConfigInsecure(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSClientConfig{InsecureSkipVerify: true})
	require.NoError(t, err)
	assert.True(t, cfg.InsecureSkipVerify)
}

func TestBuildTLSConfigServerName(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSClientConfig{ServerName: "kafka.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "kafka.example.com", cfg.ServerName)
}

func TestBuildTLSConfigInvalidCAFile(t *testing.T) {
	_, err := BuildTLSConfig(&TLSClientConfig{CAFile: "/nonexistent/ca.pem"})
	require.EqualError(t, err, "tls.ca_file: file does not exist", "the path and the OS error stay out")
}

func TestBuildTLSConfigInvalidCertKey(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))
	for _, tc := range []struct {
		name, cert, key, want string
	}{
		{name: "missing cert", cert: "/nonexistent/cert.pem", key: notPEM, want: "tls.cert_file: file does not exist"},
		{name: "missing key", cert: notPEM, key: "/nonexistent/key.pem", want: "tls.key_file: file does not exist"},
		{name: "directory", cert: dir, key: notPEM, want: "tls.cert_file: not a regular file"},
		{name: "invalid pair", cert: notPEM, key: notPEM, want: "tls.cert_file: cannot load the key pair with tls.key_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildTLSConfig(&TLSClientConfig{CertFile: tc.cert, KeyFile: tc.key})
			require.EqualError(t, err, tc.want, "the paths and the OS error stay out")
			fields, ok := errors.AsType[utils.ValidationErrors](err)
			require.True(t, ok, "the field reaches the API error")
			assert.Equal(t, strings.SplitN(tc.want, ":", 2)[0], fields[0].Field)
		})
	}
}

func TestBuildTLSConfigValidCA(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	generateSelfSignedCA(t, caFile)

	cfg, err := BuildTLSConfig(&TLSClientConfig{CAFile: caFile})
	require.NoError(t, err)
	assert.NotNil(t, cfg.RootCAs, "RootCAs must be set when CA file is valid")
}

func TestBuildTLSConfigInvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not-a-certificate"), 0o600))

	_, err := BuildTLSConfig(&TLSClientConfig{CAFile: caFile})
	require.EqualError(t, err, "tls.ca_file: no valid PEM certificate")
}

func TestBuildTLSConfigValidClientCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	generateSelfSignedCert(t, certFile, keyFile)

	cfg, err := BuildTLSConfig(&TLSClientConfig{CertFile: certFile, KeyFile: keyFile})
	require.NoError(t, err)
	require.Len(t, cfg.Certificates, 1, "must load exactly one client certificate")
}

func TestBuildTLSConfigAllOptions(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	generateSelfSignedCA(t, caFile)
	generateSelfSignedCert(t, certFile, keyFile)

	cfg, err := BuildTLSConfig(&TLSClientConfig{
		CAFile:             caFile,
		CertFile:           certFile,
		KeyFile:            keyFile,
		ServerName:         "kafka.example.com",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	assert.True(t, cfg.InsecureSkipVerify)
	assert.Equal(t, "kafka.example.com", cfg.ServerName)
	assert.NotNil(t, cfg.RootCAs)
	assert.Len(t, cfg.Certificates, 1)
}

func TestTLSClientConfigValidateEmpty(t *testing.T) {
	cfg := TLSClientConfig{}
	assert.Empty(t, cfg.Validate())
}

func TestTLSClientConfigValidateCertWithoutKey(t *testing.T) {
	cfg := TLSClientConfig{CertFile: "/some/cert.pem"}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestTLSClientConfigValidateKeyWithoutCert(t *testing.T) {
	cfg := TLSClientConfig{KeyFile: "/some/key.pem"}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestTLSClientConfigValidateNonexistentFiles(t *testing.T) {
	cfg := TLSClientConfig{
		CAFile:   "/nonexistent/ca.pem",
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}
	errs := cfg.Validate()
	assert.GreaterOrEqual(t, len(errs), 3)
}

func TestTLSClientConfigValidateValidFiles(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	generateSelfSignedCA(t, caFile)
	generateSelfSignedCert(t, certFile, keyFile)

	cfg := TLSClientConfig{CAFile: caFile, CertFile: certFile, KeyFile: keyFile}
	assert.Empty(t, cfg.Validate())
}

func generateSelfSignedCA(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
}

func generateSelfSignedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cf, err := os.Create(certPath)
	require.NoError(t, err)
	defer cf.Close()
	require.NoError(t, pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))

	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	kf, err := os.Create(keyPath)
	require.NoError(t, err)
	defer kf.Close()
	require.NoError(t, pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
}

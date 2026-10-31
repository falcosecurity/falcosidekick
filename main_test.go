// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadCACertPool(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	validFile := filepath.Join(dir, "valid.crt")
	require.NoError(t, os.WriteFile(validFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	pool, err := loadCACertPool(validFile)
	require.NoError(t, err)
	require.NotNil(t, pool)

	for name, content := range map[string]string{
		"empty":   "",
		"not PEM": "this is not a certificate\n",
	} {
		t.Run(name, func(t *testing.T) {
			caFile := filepath.Join(dir, "ca.crt")
			require.NoError(t, os.WriteFile(caFile, []byte(content), 0600))
			_, err := loadCACertPool(caFile)
			require.ErrorContains(t, err, "contains no valid PEM certificates")
		})
	}

	_, err = loadCACertPool(filepath.Join(dir, "missing.crt"))
	require.ErrorContains(t, err, "failed to read tlsserver.cacertfile")
}

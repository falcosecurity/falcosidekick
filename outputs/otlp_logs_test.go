// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	collectorlog "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestOTLPLogsExport(t *testing.T) {
	for _, protocol := range []string{"http/protobuf", GRPC} {
		for _, mode := range []string{Plaintext, "custom CA", "mutual TLS", "wrong CA"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				// OTLPLogsInit sets process environment variables. Keep these tests
				// sequential and restore both their values and any inherited settings.
				for _, prefix := range []string{"OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_LOGS_"} {
					for _, suffix := range []string{
						"ENDPOINT", "PROTOCOL", "HEADERS", "TIMEOUT", "INSECURE", "COMPRESSION",
						"CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY",
					} {
						t.Setenv(prefix+suffix, "")
					}
				}
				// Retain our single record until Shutdown, whose synchronous flush
				// returns export errors instead of sending them to the global handler.
				t.Setenv("OTEL_BLRP_SCHEDULE_DELAY", "60000")
				t.Setenv("OTEL_BLRP_MAX_EXPORT_BATCH_SIZE", "512")
				t.Setenv("OTEL_BLRP_MAX_QUEUE_SIZE", "2048")
				t.Setenv("OTEL_BLRP_EXPORT_TIMEOUT", "3000")

				var serverTLS *tls.Config
				extraEnv := make(map[string]string)
				if mode != Plaintext {
					certs := newOTLPTestCertificates(t)
					serverTLS = &tls.Config{
						MinVersion:   tls.VersionTLS12,
						Certificates: []tls.Certificate{certs.server},
					}
					extraEnv["OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE"] = certs.caFile
					if mode == "mutual TLS" {
						serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
						serverTLS.ClientCAs = certs.roots
						extraEnv["OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE"] = certs.clientCertFile
						extraEnv["OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY"] = certs.clientKeyFile
					}
					if mode == "wrong CA" {
						extraEnv["OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE"] = newOTLPTestCertificates(t).caFile
					}
				}

				endpoint, received := newOTLPTestCollector(t, protocol, serverTLS)
				config := &types.Configuration{
					OTLP: types.OTLPOutputConfig{Logs: types.OTLPLogs{
						Endpoint: endpoint, Protocol: protocol, Timeout: 1000,
						TLS: serverTLS != nil, CheckCert: true, ExtraEnvVars: extraEnv,
					}},
				}
				provider, err := OTLPLogsInit(context.Background(), config)
				require.NoError(t, err)
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					_ = provider.Shutdown(ctx)
				})
				client, err := NewClient("OTLP Logs", endpoint, types.CommonConfig{}, types.InitClientArgs{Config: config})
				require.NoError(t, err)
				client.OTLPLogsLogger = otelslog.NewLogger("falco", otelslog.WithLoggerProvider(provider))
				payload := types.FalcoPayload{
					Output: "A shell was spawned in a container", Priority: types.Warning,
					Rule: "Terminal shell in container", Source: "syscall", Hostname: "test-node",
					Tags: []string{"container", "shell"}, Time: time.Unix(1700000000, 123).UTC(),
				}
				client.OTLPLogsPost(payload)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err = provider.Shutdown(ctx)
				if mode == "wrong CA" {
					require.Error(t, err)
					select {
					case <-received:
						t.Fatal("logs reached a collector signed by an untrusted CA")
					default:
					}
					return
				}
				require.NoError(t, err)
				select {
				case request := <-received:
					require.Len(t, request.ResourceLogs, 1)
					require.Len(t, request.ResourceLogs[0].ScopeLogs, 1)
					scope := request.ResourceLogs[0].ScopeLogs[0]
					require.Equal(t, "falco", scope.Scope.Name)
					require.Len(t, scope.LogRecords, 1)
					record := scope.LogRecords[0]
					require.Equal(t, payload.Output, record.Body.GetStringValue())
					require.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, record.SeverityNumber)
					attributes := make(map[string]string)
					for _, attribute := range record.Attributes {
						attributes[attribute.Key] = attribute.Value.GetStringValue()
					}
					require.Equal(t, map[string]string{
						"priority": "Warning", "rule": payload.Rule, "source": payload.Source,
						"hostname": payload.Hostname, "tags": "container,shell", "timestamp": payload.Time.String(),
					}, attributes)
				default:
					t.Fatal("shutdown succeeded without exporting the Falco event")
				}
			})
		}
	}
}

type otlpTestCollector struct {
	collectorlog.UnimplementedLogsServiceServer
	received chan *collectorlog.ExportLogsServiceRequest
}

func (c *otlpTestCollector) Export(_ context.Context, request *collectorlog.ExportLogsServiceRequest) (*collectorlog.ExportLogsServiceResponse, error) {
	c.received <- request
	return &collectorlog.ExportLogsServiceResponse{}, nil
}

func newOTLPTestCollector(t *testing.T, protocol string, serverTLS *tls.Config) (string, <-chan *collectorlog.ExportLogsServiceRequest) {
	t.Helper()
	received := make(chan *collectorlog.ExportLogsServiceRequest, 1)
	if protocol == GRPC {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		var options []grpc.ServerOption
		scheme := "http://"
		if serverTLS != nil {
			options = append(options, grpc.Creds(credentials.NewTLS(serverTLS)))
			scheme = "https://"
		}
		server := grpc.NewServer(options...)
		collectorlog.RegisterLogsServiceServer(server, &otlpTestCollector{received: received})
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		return scheme + listener.Addr().String(), received
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/logs" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request := &collectorlog.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- request
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = serverTLS
	if serverTLS != nil {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.URL + "/v1/logs", received
}

type otlpTestCertificates struct {
	server         tls.Certificate
	roots          *x509.CertPool
	caFile         string
	clientCertFile string
	clientKeyFile  string
}

func newOTLPTestCertificates(t *testing.T) otlpTestCertificates {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OTLP test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	dir := t.TempDir()
	certs := otlpTestCertificates{
		roots: x509.NewCertPool(), caFile: filepath.Join(dir, "ca.crt"),
		clientCertFile: filepath.Join(dir, "client.crt"), clientKeyFile: filepath.Join(dir, "client.key"),
	}
	require.True(t, certs.roots.AppendCertsFromPEM(caPEM))
	require.NoError(t, os.WriteFile(certs.caFile, caPEM, 0600))
	for i, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "OTLP test peer"},
			NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if usage == x509.ExtKeyUsageServerAuth {
			certs.server, err = tls.X509KeyPair(certPEM, keyPEM)
			require.NoError(t, err)
		} else {
			require.NoError(t, os.WriteFile(certs.clientCertFile, certPEM, 0600))
			require.NoError(t, os.WriteFile(certs.clientKeyFile, keyPEM, 0600))
		}
	}
	return certs
}

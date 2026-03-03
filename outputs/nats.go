// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	nats "github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

var slugRegExp = regexp.MustCompile("[^a-z0-9]+")

const defaultNatsSubjects = "falco.<priority>.<rule>"

type natsAuthMode uint8

const (
	natsAuthModeNone natsAuthMode = iota
	natsAuthModeCredsFile
	natsAuthModeNkeySeedFile
	natsAuthModeJWTAndNkeySeedFile
)

type natsAuthFiles struct {
	credsFile    string
	nkeySeedFile string
	jwtFile      string
}

func getNatsAuthFiles(config *types.Configuration) natsAuthFiles {
	if config == nil {
		return natsAuthFiles{}
	}

	return natsAuthFiles{
		credsFile:    strings.TrimSpace(config.Nats.CredsFile),
		nkeySeedFile: strings.TrimSpace(config.Nats.NkeySeedFile),
		jwtFile:      strings.TrimSpace(config.Nats.JWTFile),
	}
}

func resolveNatsAuthMode(authFiles natsAuthFiles) (natsAuthMode, error) {
	if authFiles.credsFile != "" && (authFiles.nkeySeedFile != "" || authFiles.jwtFile != "") {
		return natsAuthModeNone, errors.New("nats auth misconfiguration: nats.credsfile cannot be combined with nats.nkeyseedfile or nats.jwtfile")
	}

	if authFiles.jwtFile != "" && authFiles.nkeySeedFile == "" {
		return natsAuthModeNone, errors.New("nats auth misconfiguration: nats.jwtfile requires nats.nkeyseedfile")
	}

	switch {
	case authFiles.credsFile != "":
		return natsAuthModeCredsFile, nil
	case authFiles.jwtFile != "" && authFiles.nkeySeedFile != "":
		return natsAuthModeJWTAndNkeySeedFile, nil
	case authFiles.nkeySeedFile != "":
		return natsAuthModeNkeySeedFile, nil
	default:
		return natsAuthModeNone, nil
	}
}

func validateNatsAuthFile(path, configKey string) error {
	_, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("nats auth misconfiguration: %s must reference a readable file: %w", configKey, err)
	}

	return nil
}

// ValidateNatsAuthConfig validates NATS auth modes and required file paths.
func ValidateNatsAuthConfig(config *types.Configuration) error {
	authFiles := getNatsAuthFiles(config)
	mode, err := resolveNatsAuthMode(authFiles)
	if err != nil {
		return err
	}

	switch mode {
	case natsAuthModeCredsFile:
		return validateNatsAuthFile(authFiles.credsFile, "nats.credsfile")
	case natsAuthModeNkeySeedFile:
		return validateNatsAuthFile(authFiles.nkeySeedFile, "nats.nkeyseedfile")
	case natsAuthModeJWTAndNkeySeedFile:
		if err = validateNatsAuthFile(authFiles.jwtFile, "nats.jwtfile"); err != nil {
			return err
		}
		return validateNatsAuthFile(authFiles.nkeySeedFile, "nats.nkeyseedfile")
	default:
		return nil
	}
}

func natsConnectOptions(config *types.Configuration) ([]nats.Option, error) {
	authFiles := getNatsAuthFiles(config)
	mode, err := resolveNatsAuthMode(authFiles)
	if err != nil {
		return nil, err
	}

	switch mode {
	case natsAuthModeCredsFile:
		return []nats.Option{nats.UserCredentials(authFiles.credsFile)}, nil
	case natsAuthModeNkeySeedFile:
		option, natsErr := nats.NkeyOptionFromSeed(authFiles.nkeySeedFile)
		if natsErr != nil {
			return nil, fmt.Errorf("nats auth misconfiguration: failed to load nats.nkeyseedfile: %w", natsErr)
		}
		return []nats.Option{option}, nil
	case natsAuthModeJWTAndNkeySeedFile:
		return []nats.Option{nats.UserCredentials(authFiles.jwtFile, authFiles.nkeySeedFile)}, nil
	default:
		return nil, nil
	}
}

func natsTLSConnectOptions(config *types.Configuration, cfg types.CommonConfig) ([]nats.Option, error) {
	if config == nil {
		return nil, nil
	}

	hostPort := strings.TrimSpace(config.Nats.HostPort)
	tlsRequested := cfg.MutualTLS || !cfg.CheckCert || config.TLSClient.CaCertFile != "" ||
		strings.HasPrefix(hostPort, "natss://") || strings.HasPrefix(hostPort, "tls://")
	if !tlsRequested {
		return nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	if config.TLSClient.CaCertFile != "" {
		caCert, readErr := os.ReadFile(config.TLSClient.CaCertFile)
		if readErr != nil {
			return nil, fmt.Errorf("nats tls misconfiguration: failed to read tlsclient.cacertfile: %w", readErr)
		}
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)
	}

	if cfg.MutualTLS {
		certPath := config.MutualTLSClient.CertFile
		if certPath == "" {
			certPath = config.MutualTLSFilesPath + MutualTLSClientCertFilename
		}

		keyPath := config.MutualTLSClient.KeyFile
		if keyPath == "" {
			keyPath = config.MutualTLSFilesPath + MutualTLSClientKeyFilename
		}

		caPath := config.MutualTLSClient.CaCertFile
		if caPath == "" {
			caPath = config.MutualTLSFilesPath + MutualTLSCacertFilename
		}

		cert, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
		if loadErr != nil {
			return nil, fmt.Errorf("nats tls misconfiguration: failed to load mutualtlsclient cert/key: %w", loadErr)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		caCert, readErr := os.ReadFile(caPath)
		if readErr != nil {
			return nil, fmt.Errorf("nats tls misconfiguration: failed to read mutualtlsclient.cacertfile: %w", readErr)
		}
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)
	} else if !cfg.CheckCert {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 This is only set as a result of explicit configuration
	}

	return []nats.Option{nats.Secure(tlsConfig)}, nil
}

// NatsPublish publishes event to NATS
func (c *Client) NatsPublish(falcopayload types.FalcoPayload) {
	c.Stats.Nats.Add(Total, 1)

	subject := c.Config.Nats.SubjectTemplate
	if len(subject) == 0 {
		subject = defaultNatsSubjects
	}

	subject = strings.ReplaceAll(subject, "<priority>", strings.ToLower(falcopayload.Priority.String()))
	subject = strings.ReplaceAll(subject, "<rule>", strings.Trim(slugRegExp.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_"))

	options, err := natsConnectOptions(c.Config)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	tlsOptions, err := natsTLSConnectOptions(c.Config, c.cfg)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	options = append(options, tlsOptions...)

	nc, err := nats.Connect(c.EndpointURL.String(), options...)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}
	defer nc.Flush()
	defer nc.Close()

	j, err := json.Marshal(falcopayload)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	err = nc.Publish(subject, j)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric("outputs", 1, []string{"output:nats", "status:ok"})
	c.Stats.Nats.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "nats"), attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "Publish OK")
}

// setNatsErrorMetrics set the error stats
func (c *Client) setNatsErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:nats", "status:error"})
	c.Stats.Nats.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "nats"),
		attribute.String("status", Error)).Inc()

}

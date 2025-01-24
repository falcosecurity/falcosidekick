// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"crypto/tls"
	"fmt"
	htmlTemplate "html/template"
	"net"
	"regexp"
	"strconv"
	"strings"
	textTemplate "text/template"

	"github.com/DataDog/datadog-go/statsd"
	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/outputs/otlpmetrics"
	"github.com/falcosecurity/falcosidekick/types"
)

const rfc2822 = "Mon Jan 02 15:04:05 -0700 2006"

// SMTPPayload is payload for SMTP Output
type SMTPPayload struct {
	From    string
	To      string
	Subject string
	Body    string
}

// NewSMTPClient returns a new output.Client for accessing a SMTP server.
func NewSMTPClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	reg := regexp.MustCompile(`.*:[0-9]+`)
	if !reg.MatchString(config.SMTP.HostPort) {
		utils.Log(utils.ErrorLvl, "SMTP", "Bad Host:Port")
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:      "SMTP",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func newSMTPPayload(falcopayload types.FalcoPayload, config *types.Configuration) SMTPPayload {
	s := SMTPPayload{
		From:    "From: " + config.SMTP.From,
		To:      "To: " + config.SMTP.To,
		Subject: "Subject: [" + falcopayload.Priority.String() + "] " + falcopayload.Output,
	}

	s.Body = "From: " + config.SMTP.From + "\n"
	s.Body += "To: " + config.SMTP.To + "\n"
	s.Body += "Date: " + falcopayload.Time.Format(rfc2822) + "\n"
	s.Body += "MIME-version: 1.0\n"

	if config.SMTP.OutputFormat != Text {
		s.Body += "Content-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM\n"
	}

	s.Body += "Content-Type: text/plain; charset=\"UTF-8\"\n\n"

	ttmpl := textTemplate.New(Text)
	ttmpl, _ = ttmpl.Parse(plaintextTmpl)
	var outtext bytes.Buffer
	err := ttmpl.Execute(&outtext, falcopayload)
	if err != nil {
		utils.Log(utils.ErrorLvl, "SMTP", err.Error())
		return s
	}
	s.Body += outtext.String()

	if config.SMTP.OutputFormat == Text {
		return s
	}

	s.Body += "--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	htmpl := htmlTemplate.New("html")
	htmpl, _ = htmpl.Parse(htmlTmpl)
	var outhtml bytes.Buffer
	err = htmpl.Execute(&outhtml, falcopayload)
	if err != nil {
		utils.Log(utils.ErrorLvl, "SMTP", err.Error())
		return s
	}
	s.Body += outhtml.String()

	return s
}

func (c *Client) ReportErr(message string, err error) {
	go c.CountMetric("outputs", 1, []string{"output:smtp", "status:error"})
	c.Stats.SMTP.Add(Error, 1)
	utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("%s : %v", message, err))
}

func (c *Client) GetAuth() (sasl.Client, error) {
	if c.Config.SMTP.AuthMechanism == "" {
		return nil, nil
	}
	var authClient sasl.Client
	switch strings.ToLower(c.Config.SMTP.AuthMechanism) {
	case Plain:
		authClient = sasl.NewPlainClient(c.Config.SMTP.Identity, c.Config.SMTP.User, c.Config.SMTP.Password)
	case OAuthBearer:
		host, portString, _ := net.SplitHostPort(c.Config.SMTP.HostPort)
		port, err := strconv.Atoi(portString)
		if err != nil {
			return nil, err
		}
		authClient = sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Username: c.Config.SMTP.User, Token: c.Config.SMTP.Token, Host: host, Port: port})
	case External:
		authClient = sasl.NewExternalClient(c.Config.SMTP.Identity)
	case Anonymous:
		authClient = sasl.NewAnonymousClient(c.Config.SMTP.Trace)
	default:
		return nil, ErrSASLAuthCreation
	}
	return authClient, nil
}

// SendMail sends email to SMTP server
func (c *Client) SendMail(falcopayload types.FalcoPayload) {
	sp := newSMTPPayload(falcopayload, c.Config)

	to := strings.Split(strings.ReplaceAll(c.Config.SMTP.To, " ", ""), ",")

	var smtpClient *smtp.Client
	var err error
	if c.Config.SMTP.TLS {
		tlsCfg := &tls.Config{
			ServerName: strings.Split(c.Config.SMTP.HostPort, ":")[0],
			MinVersion: tls.VersionTLS12,
		}
		smtpClient, err = smtp.DialStartTLS(c.Config.SMTP.HostPort, tlsCfg)
	} else {
		smtpClient, err = smtp.Dial(c.Config.SMTP.HostPort)
	}
	if err != nil {
		c.ReportErr("Client error", err)
		return
	}

	if c.Config.SMTP.AuthMechanism != None {
		auth, err := c.GetAuth()
		if err != nil {
			c.ReportErr("SASL Authentication mechanisms", err)
			return
		}
		smtpClient.Auth(auth)
	}

	body := sp.Subject + "\n" + sp.Body

	if c.Config.Debug {
		utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("payload : \nServer: %v\n%v\n%v\nSubject: %v", c.Config.SMTP.HostPort, sp.From, sp.To, sp.Subject))
		if c.Config.SMTP.AuthMechanism != "" {
			utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("SASL Auth : \nMechanisms: %v\nUser: %v\nToken: %v\nIdentity: %v\nTrace: %v", c.Config.SMTP.AuthMechanism, c.Config.SMTP.User, c.Config.SMTP.Token, c.Config.SMTP.Identity, c.Config.SMTP.Trace))
		} else {
			utils.Log(utils.DebugLvl, c.OutputType, "SASL Auth : Disabled")
		}
	}

	c.Stats.SMTP.Add("total", 1)
	err = smtpClient.SendMail(c.Config.SMTP.From, to, strings.NewReader(body))
	if err != nil {
		c.ReportErr("Send Mail failure", err)
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType, " SMTP - Sent OK\n")
	go c.CountMetric("outputs", 1, []string{"output:smtp", "status:ok"})
	c.Stats.SMTP.Add(OK, 1)
}

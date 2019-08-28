package outputs

import (
	"bytes"
	htmlTemplate "html/template"
	"log"
	"regexp"
	"strings"
	textTemplate "text/template"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
	"github.com/falcosecurity/falcosidekick/types"
)

// SMTPPayload is payload for SMTP Output
type SMTPPayload struct {
	To      string
	Subject string
	Body    string
}

// NewSMTPClient returns a new output.Client for accessing a SMTP server.
func NewSMTPClient(outputType string, config *types.Configuration, stats *types.Statistics) (*Client, error) {
	reg := regexp.MustCompile(`.*:[0-9]+`)
	if !reg.MatchString(config.SMTP.HostPort) {
		log.Printf("[ERROR] : SMTP - Bad Host:Port\n")
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType: outputType,
		Config:     config,
		Stats:      stats,
	}, nil
}

func newSMTPPayload(falcopayload types.FalcoPayload, config *types.Configuration) SMTPPayload {
	s := SMTPPayload{
		To:      "To: " + config.SMTP.To,
		Subject: "Subject: [" + falcopayload.Priority + "] " + falcopayload.Output,
	}

	s.Body = "MIME-version: 1.0;\n"

	if config.SMTP.OutputFormat != "text" {
		s.Body += "Content-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM\n"
	}

	s.Body += "Content-Type: text/plain; charset=\"UTF-8\";\n\n"

	ttmpl := textTemplate.New("text")
	ttmpl, _ = ttmpl.Parse(plaintextTmpl)
	var outtext bytes.Buffer
	err := ttmpl.Execute(&outtext, falcopayload)
	if err != nil {
		log.Printf("[ERROR] : SMTP - %v\n", err)
		return s
	}
	s.Body += outtext.String()

	if config.SMTP.OutputFormat == "text" {
		return s
	}

	s.Body += "--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	htmpl := htmlTemplate.New("html")
	htmpl, _ = htmpl.Parse(htmlTmpl)
	var outhtml bytes.Buffer
	err = htmpl.Execute(&outhtml, falcopayload)
	if err != nil {
		log.Printf("[ERROR] : SMTP - %v\n", err)
		return s
	}
	s.Body += outhtml.String()

	return s
}

// SendMail sends email to SMTP server
func (c *Client) SendMail(falcopayload types.FalcoPayload) {
	sp := newSMTPPayload(falcopayload, c.Config)

	to := strings.Split(strings.Replace(c.Config.SMTP.To, " ", "", -1), ",")
	auth := sasl.NewPlainClient("", c.Config.SMTP.User, c.Config.SMTP.Password)
	body := sp.To + "\n" + sp.Subject + "\n" + sp.Body

	if c.Config.Debug == true {
		log.Printf("[DEBUG] : SMTP payload : \nServeur: %v\nFrom: %v\nTo: %v\nSubject: %v\n", c.Config.SMTP.HostPort, c.Config.SMTP.From, sp.To, sp.Subject)
	}

	err := smtp.SendMail(c.Config.SMTP.HostPort, auth, c.Config.SMTP.From, to, strings.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] : SMTP - %v\n", err)
		return
	}

	log.Printf("[INFO]  : SMTP - Sent OK\n")

	if err != nil {
		c.Stats.SMTP.Add("error", 1)
	} else {
		c.Stats.SMTP.Add("sent", 1)
	}
	c.Stats.SMTP.Add("total", 1)
}

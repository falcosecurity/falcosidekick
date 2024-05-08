// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"log"
	"sort"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

// Field
type slackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// Attachment
type slackAttachment struct {
	Fallback   string                 `json:"fallback"`
	Color      string                 `json:"color"`
	Text       string                 `json:"text,omitempty"`
	Fields     []slackAttachmentField `json:"fields"`
	Footer     string                 `json:"footer,omitempty"`
	FooterIcon string                 `json:"footer_icon,omitempty"`
}

// Payload
type slackPayload struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func newSlackPayload(falcopayload types.FalcoPayload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)
	if config.Slack.OutputFormat == All || config.Slack.OutputFormat == Fields || config.Slack.OutputFormat == "" {
		field.Title = Rule
		field.Value = falcopayload.Rule
		field.Short = true
		fields = append(fields, field)
		field.Title = Priority
		field.Value = falcopayload.Priority.String()
		field.Short = true
		fields = append(fields, field)
		field.Title = Source
		field.Value = falcopayload.Source
		field.Short = true
		fields = append(fields, field)
		if falcopayload.Hostname != "" {
			field.Title = Hostname
			field.Value = falcopayload.Hostname
			field.Short = true
			fields = append(fields, field)
		}
		if len(falcopayload.Tags) != 0 {
			sort.Strings(falcopayload.Tags)
			field.Title = Tags
			field.Value = strings.Join(falcopayload.Tags, ", ")
			field.Short = true
			fields = append(fields, field)
		}

		for _, i := range getSortedStringKeys(falcopayload.OutputFields) {
			field.Title = i
			field.Value = falcopayload.OutputFields[i].(string)
			if len([]rune(falcopayload.OutputFields[i].(string))) < 36 {
				field.Short = true
			} else {
				field.Short = false
			}
			fields = append(fields, field)
		}

		field.Title = Time
		field.Short = false
		field.Value = falcopayload.Time.String()
		fields = append(fields, field)

		attachment.Footer = DefaultFooter
		if config.Slack.Footer != "" {
			attachment.Footer = config.Slack.Footer
		}
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if config.Slack.OutputFormat == All || config.Slack.OutputFormat == Text || config.Slack.OutputFormat == "" {
		attachment.Text = falcopayload.Output
	}

	if config.Slack.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Slack.MessageFormatTemplate.Execute(buf, falcopayload); err != nil {
			log.Printf("[ERROR] : Slack - Error expanding Slack message %v", err)
		} else {
			messageText = buf.String()
		}
	}

	var color string
	switch falcopayload.Priority {
	case types.Emergency:
		color = Red
	case types.Alert:
		color = Orange
	case types.Critical:
		color = Orange
	case types.Error:
		color = Red
	case types.Warning:
		color = Yellow
	case types.Notice:
		color = Lightcyan
	case types.Informational:
		color = LigthBlue
	case types.Debug:
		color = PaleCyan
	}
	attachment.Color = color

	attachments = append(attachments, attachment)

	s := slackPayload{
		Text:        messageText,
		Username:    config.Slack.Username,
		IconURL:     config.Slack.Icon,
		Attachments: attachments}

	if config.Slack.Channel != "" {
		s.Channel = config.Slack.Channel
	}

	return s
}

// SlackPost posts event to Slack
func (c *Client) SlackPost(falcopayload types.FalcoPayload) {
	c.Stats.Slack.Add(Total, 1)

	err := c.Post(newSlackPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:slack", "status:error"})
		c.Stats.Slack.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": Error}).Inc()
		log.Printf("[ERROR] : Slack - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:slack", "status:ok"})
	c.Stats.Slack.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": OK}).Inc()
}

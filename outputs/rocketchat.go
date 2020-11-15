package outputs

import (
	"bytes"
	"log"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

func newRocketchatPayload(falcopayload types.FalcoPayload, config *types.Configuration) slackPayload {
	var messageText string
	var attachments []slackAttachment
	var attachment slackAttachment
	var fields []slackAttachmentField
	var field slackAttachmentField

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
		for i, j := range falcopayload.OutputFields {
			switch j.(type) {
			case string:
				field.Title = i
				field.Value = j.(string)
				if len([]rune(j.(string))) < 36 {
					field.Short = true
				} else {
					field.Short = false
				}
			default:
				continue
			}
			fields = append(fields, field)
		}

		field.Title = Rule
		field.Value = falcopayload.Rule
		field.Short = true
		fields = append(fields, field)
		field.Title = Priority
		field.Value = falcopayload.Priority
		field.Short = true
		fields = append(fields, field)
		field.Title = Time
		field.Short = false
		field.Value = falcopayload.Time.String()
		fields = append(fields, field)
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
		attachment.Text = falcopayload.Output
	}

	if config.Rocketchat.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Rocketchat.MessageFormatTemplate.Execute(buf, falcopayload); err != nil {
			log.Printf("[ERROR] : Error expanding Slack message %v", err)
		} else {
			messageText = buf.String()
		}
	}

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
		var color string
		switch strings.ToLower(falcopayload.Priority) {
		case Emergency:
			color = Red
		case Alert:
			color = Orange
		case Critical:
			color = Orange
		case Error:
			color = Red
		case Warning:
			color = Yellow
		case Notice:
			color = Lightcyan
		case Informational:
			color = LigthBlue
		case Debug:
			color = PaleCyan
		}
		attachment.Color = color

		attachments = append(attachments, attachment)
	}

	iconURL := DefaultIconURL
	if config.Rocketchat.Icon != "" {
		iconURL = config.Rocketchat.Icon
	}

	s := slackPayload{
		Text:        messageText,
		Username:    "Falcosidekick",
		IconURL:     iconURL,
		Attachments: attachments}

	return s
}

// RocketchatPost posts event to Rocketchat
func (c *Client) RocketchatPost(falcopayload types.FalcoPayload) {
	err := c.Post(newRocketchatPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Rocketchat.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": Error}).Inc()
	} else {
		c.Stats.Rocketchat.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": OK}).Inc()
	}

	c.Stats.Rocketchat.Add(Total, 1)
}

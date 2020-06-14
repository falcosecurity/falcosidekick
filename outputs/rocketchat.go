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

	if config.Rocketchat.OutputFormat == "all" || config.Rocketchat.OutputFormat == "fields" || config.Rocketchat.OutputFormat == "" {
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

		field.Title = "rule"
		field.Value = falcopayload.Rule
		field.Short = true
		fields = append(fields, field)
		field.Title = "priority"
		field.Value = falcopayload.Priority
		field.Short = true
		fields = append(fields, field)
		field.Title = "time"
		field.Short = false
		field.Value = falcopayload.Time.String()
		fields = append(fields, field)
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if config.Rocketchat.OutputFormat == "all" || config.Rocketchat.OutputFormat == "fields" || config.Rocketchat.OutputFormat == "" {
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

	if config.Rocketchat.OutputFormat == "all" || config.Rocketchat.OutputFormat == "fields" || config.Rocketchat.OutputFormat == "" {
		var color string
		switch strings.ToLower(falcopayload.Priority) {
		case "emergency":
			color = "#e20b0b"
		case "alert":
			color = "#ff5400"
		case "critical":
			color = "#ff9000"
		case "error":
			color = "#ffc700"
		case "warning":
			color = "#ffff00"
		case "notice":
			color = "#5bffb5"
		case "informational":
			color = "#68c2ff"
		case "debug":
			color = "#ccfff2"
		}
		attachment.Color = color

		attachments = append(attachments, attachment)
	}

	iconURL := "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png"
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

// MattermostPost posts event to Rocketchat
func (c *Client) MattermostPost(falcopayload types.FalcoPayload) {
	err := c.Post(newRocketchatPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Rocketchat.Add("error", 1)
	} else {
		c.Stats.Rocketchat.Add("ok", 1)
	}
	c.Stats.Rocketchat.Add("total", 1)
}

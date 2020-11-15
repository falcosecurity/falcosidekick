package outputs

import (
	"bytes"
	"log"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

func newMattermostPayload(falcopayload types.FalcoPayload, config *types.Configuration) slackPayload {
	var messageText string
	var attachments []slackAttachment
	var attachment slackAttachment
	var fields []slackAttachmentField
	var field slackAttachmentField

	if config.Mattermost.OutputFormat == All || config.Mattermost.OutputFormat == Fields || config.Mattermost.OutputFormat == "" {
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

		attachment.Footer = DefaultFooter
		if config.Mattermost.Footer != "" {
			attachment.Footer = config.Mattermost.Footer
		}
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if config.Mattermost.OutputFormat == All || config.Mattermost.OutputFormat == Fields || config.Mattermost.OutputFormat == "" {
		attachment.Text = falcopayload.Output
	}

	if config.Mattermost.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Mattermost.MessageFormatTemplate.Execute(buf, falcopayload); err != nil {
			log.Printf("[ERROR] : Error expanding Slack message %v", err)
		} else {
			messageText = buf.String()
		}
	}

	var color string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency":
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

	iconURL := DefaultIconURL
	if config.Mattermost.Icon != "" {
		iconURL = config.Mattermost.Icon
	}

	s := slackPayload{
		Text:        messageText,
		Username:    "Falcosidekick",
		IconURL:     iconURL,
		Attachments: attachments,
	}

	return s
}

// MattermostPost posts event to Mattermost
func (c *Client) MattermostPost(falcopayload types.FalcoPayload) {
	err := c.Post(newMattermostPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Mattermost.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "mattermost", "status": Error}).Inc()
	} else {
		c.Stats.Mattermost.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "mattermost", "status": OK}).Inc()
	}

	c.Stats.Mattermost.Add(Total, 1)
}

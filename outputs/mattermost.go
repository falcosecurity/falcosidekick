package outputs

import (
	"bytes"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

func newMattermostPayload(falcopayload types.FalcoPayload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)

	if config.Mattermost.OutputFormat == All || config.Mattermost.OutputFormat == Fields || config.Mattermost.OutputFormat == "" {
		for i, j := range falcopayload.OutputFields {
			switch v := j.(type) {
			case string:
				field.Title = i
				field.Value = v
				if len([]rune(v)) < 36 {
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
		field.Value = falcopayload.Priority.String()
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
			log.Printf("[ERROR] : Mattermost - Error expanding Mattermost message %v", err)
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
	c.Stats.Mattermost.Add(Total, 1)

	err := c.Post(newMattermostPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:mattermost", "status:error"})
		c.Stats.Mattermost.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "mattermost", "status": Error}).Inc()
		log.Printf("[ERROR] : Mattermost - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:mattermost", "status:ok"})
	c.Stats.Mattermost.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "mattermost", "status": OK}).Inc()
	log.Printf("[INFO] : Mattermost - Publish OK\n")
}

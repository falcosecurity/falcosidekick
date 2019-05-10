package outputs

import (
	"os"

	"github.com/Issif/falcosidekick/types"
)

// Field
type slackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

//Attachment
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
	Username    string            `json:"username,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func newSlackPayload(falcopayload types.FalcoPayload) slackPayload {
	var attachments []slackAttachment
	var attachment slackAttachment
	var fields []slackAttachmentField
	var field slackAttachmentField

	if os.Getenv("SLACK_OUTPUT_FORMAT") == "all" || os.Getenv("SLACK_OUTPUT_FORMAT") == "fields" || os.Getenv("SLACK_OUTPUT_FORMAT") == "" {
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

		if os.Getenv("SLACK_FOOTER") != "" {
			attachment.Footer = os.Getenv("SLACK_FOOTER")
		} else {
			attachment.Footer = "https://github.com/Issif/falcosidekick"
		}
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if os.Getenv("SLACK_OUTPUT_FORMAT") == "all" || os.Getenv("SLACK_OUTPUT_FORMAT") == "text" || os.Getenv("SLACK_OUTPUT_FORMAT") == "" {
		attachment.Text = falcopayload.Output
	}

	var color string
	switch falcopayload.Priority {
	case "Emergency":
		color = "#e20b0b"
	case "Alert":
		color = "#ff5400"
	case "Critical":
		color = "#ff9000"
	case "Error":
		color = "#ffc700"
	case "Warning":
		color = "#ffff00"
	case "Notice":
		color = "#5bffb5"
	case "Informationnal":
		color = "#68c2ff"
	case "Debug":
		color = "#ccfff2"
	}
	attachment.Color = color

	attachments = append(attachments, attachment)

	var iconUrl string
	if os.Getenv("SLACK_ICON") != "" {
		iconUrl = os.Getenv("SLACK_ICON")
	} else {
		iconUrl = "https://raw.githubusercontent.com/Issif/falcosidekick/master/imgs/falcosidekick.png"
	}

	slackPayload := slackPayload{
		Username:    "Falco Sidekick",
		IconURL:     iconUrl,
		Attachments: attachments}

	return slackPayload
}

// slackPost posts event to Slack
func (c *Client) SlackPost(falcopayload types.FalcoPayload) {
	c.Post(newSlackPayload(falcopayload))
}

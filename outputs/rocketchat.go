// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"log"
	"sort"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

func newRocketchatPayload(falcopayload types.FalcoPayload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
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
		if falcopayload.Hostname != "" {
			field.Title = Hostname
			field.Value = falcopayload.Hostname
			field.Short = true
			fields = append(fields, field)
		}
	}

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Text || config.Rocketchat.OutputFormat == "" {
		attachment.Text = falcopayload.Output
	}

	if config.Rocketchat.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Rocketchat.MessageFormatTemplate.Execute(buf, falcopayload); err != nil {
			log.Printf("[ERROR] : RocketChat - Error expanding RocketChat message %v", err)
		} else {
			messageText = buf.String()
		}
	}

	if config.Rocketchat.OutputFormat == All || config.Rocketchat.OutputFormat == Fields || config.Rocketchat.OutputFormat == "" {
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
	}

	iconURL := DefaultIconURL
	if config.Rocketchat.Icon != "" {
		iconURL = config.Rocketchat.Icon
	}

	s := slackPayload{
		Text:        messageText,
		Username:    config.Rocketchat.Username,
		IconURL:     iconURL,
		Attachments: attachments}

	return s
}

// RocketchatPost posts event to Rocketchat
func (c *Client) RocketchatPost(falcopayload types.FalcoPayload) {
	c.Stats.Rocketchat.Add(Total, 1)

	err := c.Post(newRocketchatPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:rocketchat", "status:error"})
		c.Stats.Rocketchat.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": Error}).Inc()
		log.Printf("[ERROR] : RocketChat - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:rocketchat", "status:ok"})
	c.Stats.Rocketchat.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "rocketchat", "status": OK}).Inc()
}

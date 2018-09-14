package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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
	PreText    string                 `json:"pretext,omitempty"`
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

func newSlackPayload(falcopayload falcoPayload) slackPayload {
	var attachments []slackAttachment
	var attachment slackAttachment
	var fields []slackAttachmentField
	var field slackAttachmentField

	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			field.Title = i
			field.Value = j.(string)
			field.Short = true
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

	attachment.Fallback = falcopayload.Output
	attachment.Fields = fields
	attachment.PreText = falcopayload.Output
	attachment.Footer = "https://github.com/Issif/falcosidekick"

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

	slackPayload := slackPayload{
		Username:    "Falco Sidekick",
		IconURL:     "https://raw.githubusercontent.com/Issif/falcosidekick/master/falcosidekick.png",
		Attachments: attachments}

	return slackPayload
}

// slackPost posts event to slack
func slackPost(falcopayload falcoPayload) {
	slackPayload := newSlackPayload(falcopayload)
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(slackPayload)
	_, err := http.Post(slackToken, "application/json; charset=utf-8", b)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
}

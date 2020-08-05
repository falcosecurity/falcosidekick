package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type discordPayload struct {
	Content   string                `json:"content"`
	AvatarURL string                `json:"avatar_url,omitempty"`
	Embeds    []discordEmbedPayload `json:"embeds"`
}

type discordEmbedPayload struct {
	Title       string                     `json:"title"`
	URL         string                     `json:"url"`
	Description string                     `json:"description"`
	Color       string                     `json:"color"`
	Fields      []discordEmbedFieldPayload `json:"fields"`
}

type discordEmbedFieldPayload struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func newDiscordPayload(falcopayload types.FalcoPayload, config *types.Configuration) discordPayload {
	var iconURL string
	if config.Discord.Icon != "" {
		iconURL = config.Discord.Icon
	} else {
		iconURL = "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png"
	}

	var color string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency":
		color = "15158332" // red
	case "alert":
		color = "11027200" // dark orange
	case "critical":
		color = "15105570" // orange
	case "error":
		color = "15844367" // gold
	case "warning":
		color = "12745742" // dark gold
	case "notice":
		color = "3066993" // teal
	case "informational":
		color = "3447003" // blue
	case "debug":
		color = "12370112" // light grey
	}

	embeds := make([]discordEmbedPayload, 0)

	embedFields := make([]discordEmbedFieldPayload, 0)
	var embedField discordEmbedFieldPayload

	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			embedField.Name = i
			embedField.Inline = true
			embedField.Value = "```" + j.(string) + "```"
		default:
			continue
		}
		embedFields = append(embedFields, embedField)
	}
	embedField.Name = "rule"
	embedField.Value = falcopayload.Rule
	embedField.Inline = true
	embedFields = append(embedFields, embedField)
	embedField.Name = "priority"
	embedField.Value = falcopayload.Priority
	embedField.Inline = true
	embedFields = append(embedFields, embedField)
	embedField.Name = "time"
	embedField.Value = falcopayload.Time.String()
	embedField.Inline = true
	embedFields = append(embedFields, embedField)

	embed := discordEmbedPayload{
		Title:       "",
		Description: falcopayload.Output,
		Color:       color,
		Fields:      embedFields,
	}
	embeds = append(embeds, embed)

	ds := discordPayload{
		Content:   "",
		AvatarURL: iconURL,
		Embeds:    embeds,
	}
	return ds
}

// DiscordPost posts events to discord
func (c *Client) DiscordPost(falcopayload types.FalcoPayload) {
	err := c.Post(newDiscordPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Discord.Add("error", 1)
	} else {
		c.Stats.Discord.Add("ok", 1)
	}
	c.Stats.Discord.Add("total", 1)
}

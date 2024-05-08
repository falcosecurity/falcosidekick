// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"sort"
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
		iconURL = DefaultIconURL
	}

	var color string
	switch falcopayload.Priority {
	case types.Emergency:
		color = "15158332" // red
	case types.Alert:
		color = "11027200" // dark orange
	case types.Critical:
		color = "15105570" // orange
	case types.Error:
		color = "15844367" // gold
	case types.Warning:
		color = "12745742" // dark gold
	case types.Notice:
		color = "3066993" // teal
	case types.Informational:
		color = "3447003" // blue
	case types.Debug:
		color = "12370112" // light grey
	}

	embeds := make([]discordEmbedPayload, 0)

	embedFields := make([]discordEmbedFieldPayload, 0)
	var embedField discordEmbedFieldPayload

	embedFields = append(embedFields, discordEmbedFieldPayload{Rule, falcopayload.Rule, true})
	embedFields = append(embedFields, discordEmbedFieldPayload{Priority, falcopayload.Priority.String(), true})
	embedFields = append(embedFields, discordEmbedFieldPayload{Source, falcopayload.Source, true})
	if falcopayload.Hostname != "" {
		embedFields = append(embedFields, discordEmbedFieldPayload{Hostname, falcopayload.Hostname, true})
	}

	for _, i := range getSortedStringKeys(falcopayload.OutputFields) {
		embedField = discordEmbedFieldPayload{i, fmt.Sprintf("```%v```", falcopayload.OutputFields[i]), true}
		embedFields = append(embedFields, embedField)
	}
	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		embedFields = append(embedFields, discordEmbedFieldPayload{Tags, strings.Join(falcopayload.Tags, ", "), true})
	}
	embedFields = append(embedFields, discordEmbedFieldPayload{Time, falcopayload.Time.String(), true})

	embed := discordEmbedPayload{
		Title:       "",
		Description: falcopayload.Output,
		Color:       color,
		Fields:      embedFields,
	}
	embeds = append(embeds, embed)

	return discordPayload{
		Content:   "",
		AvatarURL: iconURL,
		Embeds:    embeds,
	}
}

// DiscordPost posts events to discord
func (c *Client) DiscordPost(falcopayload types.FalcoPayload) {
	c.Stats.Discord.Add(Total, 1)

	err := c.Post(newDiscordPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:discord", "status:error"})
		c.Stats.Discord.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "discord", "status": Error}).Inc()
		log.Printf("[ERROR] : Discord - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:discord", "status:ok"})
	c.Stats.Discord.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "discord", "status": OK}).Inc()
}

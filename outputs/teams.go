package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsSection struct {
	ActivityTitle    string      `json:"activityTitle"`
	ActivitySubTitle string      `json:"activitySubtitle"`
	ActivityImage    string      `json:"activityImage,omitempty"`
	Text             string      `json:"text"`
	Facts            []teamsFact `json:"facts,omitempty"`
}

// Payload
type teamsPayload struct {
	Type       string         `json:"@type"`
	Summary    string         `json:"summary,omitempty"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Sections   []teamsSection `json:"sections"`
}

func newTeamsPayload(falcopayload types.FalcoPayload, config *types.Configuration) teamsPayload {
	var sections []teamsSection
	var section teamsSection
	var facts []teamsFact
	var fact teamsFact

	section.ActivityTitle = "Falco Sidekick"
	section.ActivitySubTitle = falcopayload.Time.String()

	if config.Teams.OutputFormat == "all" || config.Teams.OutputFormat == "text" || config.Teams.OutputFormat == "" {
		section.Text = falcopayload.Output
	}

	if config.Teams.ActivityImage != "" {
		section.ActivityImage = config.Teams.ActivityImage
	}

	if config.Teams.OutputFormat == "all" || config.Teams.OutputFormat == "facts" || config.Teams.OutputFormat == "" {
		for i, j := range falcopayload.OutputFields {
			switch j.(type) {
			case string:
				fact.Name = i
				fact.Value = j.(string)
			default:
				continue
			}
			facts = append(facts, fact)
		}

		fact.Name = "rule"
		fact.Value = falcopayload.Rule
		facts = append(facts, fact)
		fact.Name = "priority"
		fact.Value = falcopayload.Priority
		facts = append(facts, fact)
	}

	section.Facts = facts

	var color string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency":
		color = "e20b0b"
	case "alert":
		color = "ff5400"
	case "critical":
		color = "ff9000"
	case "error":
		color = "ffc700"
	case "warning":
		color = "ffff00"
	case "notice":
		color = "5bffb5"
	case "informationnal":
		color = "68c2ff"
	case "debug":
		color = "ccfff2"
	}

	sections = append(sections, section)

	t := teamsPayload{
		Type:       "MessageCard",
		Summary:    falcopayload.Output,
		ThemeColor: color,
		Sections:   sections,
	}

	return t
}

// TeamsPost posts event to Teams
func (c *Client) TeamsPost(falcopayload types.FalcoPayload) {
	err := c.Post(newTeamsPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Teams.Add("error", 1)
	} else {
		c.Stats.Teams.Add("sent", 1)
	}
	c.Stats.Teams.Add("total", 1)
}

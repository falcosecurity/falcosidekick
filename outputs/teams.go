package outputs

import (
	"strings"

	"github.com/Issif/falcosidekick/types"
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

// {
// 	"@type": "MessageCard",
// 	"@context": "https://schema.org/extensions",
// 	"summary": "Issue 176715375",
// 	"themeColor": "EE0000",
// 	"sections": [
// 		{
// 			"activityTitle": "Falco Sidekick",
// 			"activitySubtitle": "2019-05-17T15:31:56.746609046Z",
// 			"activityImage": "https://raw.githubusercontent.com/Issif/falcosidekick/master/imgs/falcosidekick.png",
// 			"facts": [
// 				{
// 					"name": "fd.name",
// 					"value": "/bin/hack"
// 				},
// 				{
// 					"name": "proc.cmdline",
// 					"value": "touch /bin/hack"
// 				},
// 				{
// 					"name": "user.name",
// 					"value": "root"
// 				}
// 			],
// 			"text": "Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)"
// 		}
// 	]
// }

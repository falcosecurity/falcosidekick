// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// Cliq API reference: https://www.zoho.com/cliq/help/restapi/v2/

// Cliq constants
const (
	tableSlideType = "table"
	textSlideType  = "text"
	botName        = "Falco Sidekick"
)

// Table slide fields
var tableSlideHeaders = []string{"field", "value"}

// Emoji runes
const (
	emergencyEmoji   = '\U0001F6A8'
	errorEmoji       = '\U0001F7E0'
	warningEmoji     = '\U0001F7E1'
	noticeEmoji      = '\U0001F535'
	informationEmoji = '\U0001F7E2'
	debugEmoji       = '\U000026AA'
)

// Cliq table slide: https://www.zoho.com/cliq/help/restapi/v2/#attaching_content_table

// Table slide row
type cliqTableRow struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// Table slide data
type cliqTableData struct {
	Headers []string       `json:"headers"`
	Rows    []cliqTableRow `json:"rows"`
}

// Slide
type cliqSlide struct {
	Type  string      `json:"type"`
	Title string      `json:"title,omitempty"`
	Data  interface{} `json:"data"`
}

type cliqBot struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

// Payload
type cliqPayload struct {
	Text   string      `json:"text"`
	Bot    cliqBot     `json:"bot,omitempty"`
	Slides []cliqSlide `json:"slides,omitempty"`
}

func newCliqPayload(falcopayload types.FalcoPayload, config *types.Configuration) cliqPayload {
	var (
		payload cliqPayload
		field   cliqTableRow
		table   cliqTableData
	)

	payload.Bot.Name = botName

	if config.Cliq.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Cliq.MessageFormatTemplate.Execute(buf, falcopayload); err != nil {
			log.Printf("[ERROR] : Cliq - Error expanding Cliq message %v", err)
		} else {
			payload.Text = buf.String()

			if config.Cliq.OutputFormat == All || config.Cliq.OutputFormat == Text || config.Cliq.OutputFormat == "" {
				slide := cliqSlide{
					Type: textSlideType,
					Data: falcopayload.Output,
				}
				payload.Slides = append(payload.Slides, slide)
			}
		}
	} else {
		payload.Text = falcopayload.Output
	}

	if config.Cliq.OutputFormat == All || config.Cliq.OutputFormat == Fields || config.Cliq.OutputFormat == "" {
		field.Field = Rule
		field.Value = falcopayload.Rule
		table.Rows = append(table.Rows, field)

		field.Field = Priority
		field.Value = falcopayload.Priority.String()
		table.Rows = append(table.Rows, field)

		if falcopayload.Hostname != "" {
			field.Field = Hostname
			field.Value = falcopayload.Hostname
			table.Rows = append(table.Rows, field)
		}

		for _, i := range getSortedStringKeys(falcopayload.OutputFields) {
			field.Field = i
			field.Value = falcopayload.OutputFields[i].(string)
			table.Rows = append(table.Rows, field)
		}

		field.Field = Time
		field.Value = falcopayload.Time.String()
		table.Rows = append(table.Rows, field)

		table.Headers = tableSlideHeaders
		slide := cliqSlide{
			Type: tableSlideType,
			Data: &table,
		}
		payload.Slides = append(payload.Slides, slide)
	}

	if config.Cliq.UseEmoji {
		var emoji rune
		switch falcopayload.Priority {
		case types.Emergency:
			emoji = emergencyEmoji
		case types.Alert:
			emoji = errorEmoji
		case types.Critical:
			emoji = errorEmoji
		case types.Error:
			emoji = emergencyEmoji
		case types.Warning:
			emoji = warningEmoji
		case types.Notice:
			emoji = noticeEmoji
		case types.Informational:
			emoji = informationEmoji
		case types.Debug:
			emoji = debugEmoji
		default:
			emoji = '?'
		}
		payload.Text = fmt.Sprintf("%c %s", emoji, payload.Text)
	}

	if config.Cliq.Icon != "" {
		payload.Bot.Image = config.Cliq.Icon
	} else {
		payload.Bot.Image = DefaultIconURL
	}

	return payload
}

// CliqPost posts event to cliq
func (c *Client) CliqPost(falcopayload types.FalcoPayload) {
	c.Stats.Cliq.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader(ContentTypeHeaderKey, "application/json")
	err := c.Post(newCliqPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:cliq", "status:error"})
		c.Stats.Cliq.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "cliq", "status": Error}).Inc()
		log.Printf("[ERROR] : Cliq - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:cliq", "status:ok"})
	c.Stats.Cliq.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "cliq", "status": OK}).Inc()
}

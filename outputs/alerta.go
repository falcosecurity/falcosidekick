package outputs

type alertaPayload struct {
	Resource    string            `json:"resource"`
	Event       string            `json:"event"`
	Environment string            `json:"environment"`
	Severity    string            `json:"severity"`
	Correlate   []string          `json:"correlate"`
	Status      string            `json:"status"`
	Service     []string          `json:"service"`
	Group       string            `json:"group"`
	Value       string            `json:"value"`
	Text        string            `json:"text"`
	Tags        []string          `json:"tags"`
	Attributes  map[string]string `json:"attributes"`
	Origin      string            `json:"origin"`
	Type        string            `json:"type"`
	// Note: this must be an ISO 8601 formatted string in UTC time
	// ex: 2017-06-19T11:16:19.744Z
	CreateTime string `json:"createTime"`
	Timeout    int    `json:"timeout"`
	RawData    string `json:"rawData"`
}

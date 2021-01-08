package outputs

const (
	OK            string = "ok"
	Warning       string = "warning"
	Alert         string = "alert"
	Error         string = "error"
	Critical      string = "critical"
	Emergency     string = "emergency"
	Notice        string = "notice"
	Informational string = "informational"
	Debug         string = "debug"
	Info          string = "info"
	None          string = "none"

	All      string = "all"
	Fields   string = "fields"
	Total    string = "total"
	Rejected string = "rejected"
	Accepted string = "accepted"
	Outputs  string = "outputs"

	Rule     string = "rule"
	Priority string = "priority"
	Time     string = "time"
	Text     string = "text"

	DefaultFooter  string = "https://github.com/falcosecurity/falcosidekick"
	DefaultIconURL string = "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png"

	// Colors
	PaleCyan  string = "#ccfff2"
	Yellow    string = "#ffc700"
	Red       string = "#e20b0b"
	LigthBlue string = "#68c2ff"
	Lightcyan string = "#5bffb5"
	Orange    string = "#ff5400"

	Kubeless string = "Kubeless"
)

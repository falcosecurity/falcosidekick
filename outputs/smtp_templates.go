// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

var plaintextTmpl = `Priority: {{ .Priority }}
Output: {{ .Output }}
Rule: {{ .Rule }}
Source: {{ .Source }}
Hostname: {{ .Hostname }}
Tags: {{ range .Tags }}{{ . }} {{ end }}
Time: {{ .Time }}

--Fields--
{{ range $key, $value := .OutputFields }}{{ $key }}: {{ $value }}
{{ end }}

`

var htmlTmpl = `
{{ $color := "#858585" }}
{{ $prio := printf "%v" .Priority }}
{{ if or (eq $prio "Emergency") (eq $prio "emergency") }}{{ $color = "#e20b0b" }}{{ end }}
{{ if or (eq $prio "Alert") (eq $prio "Alert") }}{{ $color = "#ff5400" }}{{ end }}
{{ if or (eq $prio "Critical") (eq $prio "critical") }}{{ $color = "#ff9000" }}{{ end }}
{{ if or (eq $prio "Error") (eq $prio "error") }}{{ $color = "#ffc700" }}{{ end }}
{{ if or (eq $prio "Warning") (eq $prio "warning") }}{{ $color = "#ffff00" }}{{ end }}
{{ if or (eq $prio "Notice") (eq $prio "notice") }}{{ $color = "#5bffb5" }}{{ end }}
{{ if or (eq $prio "Informational") (eq $prio "informational") }}{{ $color = "#68c2ff" }}{{ end }}
{{ if or (eq $prio "Debug") (eq $prio "debug") }}{{ $color = "#ccfff2" }}{{ end }}

<meta http-equiv="Content-Type" content="text/html; charset=us-ascii">
<style type="text/css">
    td{font-family:arial,helvetica,sans-serif;}
</style>

<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px;">
    <tbody>
        <tr>
            <td><img src="https://raw.githubusercontent.com/cncf/artwork/master/projects/falco/horizontal/color/falco-horizontal-color.png" width="117px" height="47"></td>
            <td></td>
        </tr>
    </tbody>
</table>
<br>
<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px;">
    <tbody>
        <tr>
            <td style="background-color:{{ $color }}; width:700px; text-align:center;"><span style="font-size:12px; color:#fff;"><strong>{{ .Priority }}</strong></span></td>
        </tr>
    </tbody>
</table>
<table cellpadding="5" cellspacing="0" style="font-family:arial,helvetica,sans-serif; width:700px; font-size:13px">
    <tbody>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Output</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Output }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Rule</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Rule }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Source</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Source }}</td>
        </tr>
		<tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Hostname</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Hostname }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Tags</strong></span></td>
            <td style="background-color:#d1d6da">{{ range .Tags }}{{ . }} {{ end }}</td>
        </tr>
        <tr>
            <td style="background-color:#858585"><span style="font-size:14px;color:#fff;"><strong>Time</strong></span></td>
            <td style="background-color:#d1d6da">{{ .Time }}</td>
        </tr>
    </tbody>
</table>
<br>

<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px; font-size:13px">
    <tbody>
        <tr>
            <td style="background-color: #858585; width:700px; text-align:center;"><span style="font-size:12px; color:#fff;"><strong>Fields</strong></span></td>
        </tr>
    </tbody>
</table>

<table cellpadding="3" cellspacing="0" style="font-family:arial,helvetica,sans-serif; height:2px; width:700px; font-size:13px">
    <tbody>{{ range $key, $value := .OutputFields }}
        <tr>
            <td width="1" style="background-color:#858585"><span style="font-size:14px; color:#fff;"><strong>{{ $key }}</strong></span></td>
            <td style="background-color:#d1d6da">{{ $value }}</td>
        </tr>
    {{ end }}</tbody>
</table>

--4t74weu9byeSdJTM--`

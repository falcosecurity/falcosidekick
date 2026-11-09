{{/*
Chart name.
*/}}
{{- define "falcosidekick.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full name of the resources, at most 63 characters.
*/}}
{{- define "falcosidekick.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "falcosidekick.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "falcosidekick.labels" -}}
helm.sh/chart: {{ include "falcosidekick.chart" . }}
{{ include "falcosidekick.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "falcosidekick.selectorLabels" -}}
app.kubernetes.io/name: {{ include "falcosidekick.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "falcosidekick.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "falcosidekick.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference: repository@digest, else repository:tag with the variant suffix.
*/}}
{{- define "falcosidekick.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{ if .Values.image.variant }}-{{ .Values.image.variant }}{{ end }}{{- end -}}
{{- end }}

{{/*
Refuses values the chart cannot deploy, with every problem in one message.
*/}}
{{- define "falcosidekick.validate" -}}
{{- $errs := list }}
{{- if not (has .Values.image.variant (list "" "slim")) }}
{{- $errs = append $errs (printf "image.variant %q is not supported: use \"\" or \"slim\"" .Values.image.variant) }}
{{- end }}
{{- if not (has .Values.database.backend (list "inmemory" "sqlite" "postgres")) }}
{{- $errs = append $errs (printf "database.backend %q is not supported: use inmemory, sqlite or postgres" .Values.database.backend) }}
{{- end }}
{{- if and (eq .Values.image.variant "slim") .Values.ui.enabled }}
{{- $errs = append $errs "image.variant slim has no web UI: set ui.enabled=false or use the default variant" }}
{{- end }}
{{- if and (eq .Values.database.backend "sqlite") (gt (int .Values.replicaCount) 1) }}
{{- $errs = append $errs "database.backend sqlite supports replicaCount 1 only: a ReadWriteOnce volume cannot be mounted by two pods, and a sqlite file written by two processes gets corrupted; use database.backend postgres to run several replicas" }}
{{- end }}
{{- if $errs }}
{{- fail (printf "\n%s" (join "\n" $errs)) }}
{{- end }}
{{- end }}

{{- define "falcosidekick.secretDir" -}}
/etc/falcosidekick/secrets/{{ . }}
{{- end }}

{{/*
sidekick.yaml: .Values.config with the keys the chart manages.
*/}}
{{- define "falcosidekick.sidekickConfig" -}}
{{- $cfg := deepCopy (.Values.config | default dict) }}
{{- range $key := list "ui" "api" "database" "management" "tls" }}
{{- if not (kindIs "map" (get $cfg $key)) }}
{{- $_ := set $cfg $key dict }}
{{- end }}
{{- end }}
{{- if .Values.ui.enabled }}
{{- $_ := set $cfg.ui "enabled" true }}
{{- if not $cfg.ui.event_source }}
{{- $_ := set $cfg.ui "event_source" "inmemory" }}
{{- end }}
{{- if not (hasKey $cfg.api "allow_writes") }}
{{- $_ := set $cfg.api "allow_writes" false }}
{{- end }}
{{- else }}
{{- $_ := set $cfg.ui "enabled" false }}
{{- end }}
{{- if .Values.secrets }}
{{- $dirs := $cfg.api.secret_dirs | default list }}
{{- range .Values.secrets }}
{{- $dirs = append $dirs (include "falcosidekick.secretDir" .) }}
{{- end }}
{{- $_ := set $cfg.api "secret_dirs" (uniq $dirs) }}
{{- end }}
{{- if .Values.management.service.enabled }}
{{- $_ := set $cfg.management "listen_address" "::" }}
{{- end }}
{{- if .Values.tls.secretName }}
{{- if not $cfg.tls.cert_file }}
{{- $_ := set $cfg.tls "cert_file" "/etc/falcosidekick/tls/tls.crt" }}
{{- end }}
{{- if not $cfg.tls.key_file }}
{{- $_ := set $cfg.tls "key_file" "/etc/falcosidekick/tls/tls.key" }}
{{- end }}
{{- if and $cfg.tls.mutual_tls (not $cfg.tls.ca_file) }}
{{- $_ := set $cfg.tls "ca_file" "/etc/falcosidekick/tls/ca.crt" }}
{{- end }}
{{- end }}
{{- $_ := set $cfg.database "backend" .Values.database.backend }}
{{- if eq .Values.database.backend "sqlite" }}
{{- if not (kindIs "map" $cfg.database.sqlite) }}
{{- $_ := set $cfg.database "sqlite" dict }}
{{- end }}
{{- $_ := set $cfg.database.sqlite "path" "/var/lib/falcosidekick/sidekick.db" }}
{{- end }}
{{- if and (eq .Values.database.backend "postgres") .Values.database.postgres.passwordSecret.name }}
{{- if not (kindIs "map" $cfg.database.postgres) }}
{{- $_ := set $cfg.database "postgres" dict }}
{{- end }}
{{- $_ := set $cfg.database.postgres "password_file" (printf "/etc/falcosidekick/postgres/%s" .Values.database.postgres.passwordSecret.key) }}
{{- end }}
{{- range $key := list "ui" "api" "database" "management" "tls" }}
{{- if not (get $cfg $key) }}
{{- $_ := unset $cfg $key }}
{{- end }}
{{- end }}
{{- toYaml $cfg }}
{{- end }}

{{/*
outputs.yaml: .Values.outputs, plus the inmemory output the UI reads when none is configured.
*/}}
{{- define "falcosidekick.outputsConfig" -}}
{{- $outputs := deepCopy (.Values.outputs | default dict) }}
{{- $cfg := include "falcosidekick.sidekickConfig" . | fromYaml }}
{{- if and .Values.ui.enabled (eq $cfg.ui.event_source "inmemory") (not (hasKey $outputs "inmemory")) }}
{{- $_ := set $outputs "inmemory" dict }}
{{- end }}
{{- toYaml (dict "outputs" $outputs) }}
{{- end }}

{{/*
Seconds of a Go duration (such as 5s, 1m30s, 500ms) or of a number of nanoseconds.
*/}}
{{- define "falcosidekick.durationSeconds" -}}
{{- $seconds := 0.0 }}
{{- if kindIs "string" . }}
{{- if not (regexMatch "^(0|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$" .) }}
{{- fail (printf "config.shutdown_delay %q is not a duration such as 5s or 1m30s" .) }}
{{- end }}
{{- $units := dict "h" 3600.0 "m" 60.0 "s" 1.0 "ms" 0.001 "us" 0.000001 "µs" 0.000001 "ns" 0.000000001 }}
{{- range regexFindAll "[0-9.]+[a-zµ]+" . -1 }}
{{- $number := regexFind "^[0-9.]+" . }}
{{- $seconds = addf $seconds (mulf (float64 $number) (get $units (trimPrefix $number .))) }}
{{- end }}
{{- else if . }}
{{- $seconds = divf (float64 .) 1000000000.0 }}
{{- end }}
{{- $seconds }}
{{- end }}

{{/*
shutdown_delay, plus the 10s the process gives the server and the outputs to drain, plus 5s of margin.
*/}}
{{- define "falcosidekick.terminationGracePeriodSeconds" -}}
{{- $cfg := include "falcosidekick.sidekickConfig" . | fromYaml }}
{{- $delay := hasKey $cfg "shutdown_delay" | ternary $cfg.shutdown_delay "5s" }}
{{- add (ceil (float64 (include "falcosidekick.durationSeconds" $delay))) 15 }}
{{- end }}

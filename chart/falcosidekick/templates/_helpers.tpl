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

{{/*
Full name with a suffix, such as -management, shortened so the result has at most 63 characters.
Takes a dict with ctx and suffix.
*/}}
{{- define "falcosidekick.suffixedName" -}}
{{- $base := include "falcosidekick.fullname" .ctx | trunc (int (sub 63 (len .suffix))) | trimSuffix "-" }}
{{- printf "%s%s" $base .suffix }}
{{- end }}

{{/*
Name of the ClusterRole and its binding: cluster scoped, so it carries the namespace. Both names
have at most 63 characters, so the result stays far below the 253 of a ClusterRole name.
*/}}
{{- define "falcosidekick.policyReportRoleName" -}}
{{- printf "%s-%s-policyreport" .Release.Namespace (include "falcosidekick.fullname" .) }}
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
Image reference: [registry/]repository@digest, else [registry/]repository:tag with the variant suffix.
*/}}
{{- define "falcosidekick.image" -}}
{{- $repository := .Values.image.repository }}
{{- if .Values.image.registry }}
{{- $repository = printf "%s/%s" .Values.image.registry $repository }}
{{- end }}
{{- if .Values.image.digest -}}
{{ $repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ $repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{ if .Values.image.variant }}-{{ .Values.image.variant }}{{ end }}{{- end -}}
{{- end }}

{{/*
Whether a value is set the way the runtime counts it: an empty string, map or list is not.
Renders "true" or nothing.
*/}}
{{- define "falcosidekick.isSet" -}}
{{- if kindIs "invalid" . }}
{{- else if or (kindIs "string" .) (kindIs "map" .) (kindIs "slice" .) }}
{{- if gt (len .) 0 }}true{{ end }}
{{- else }}true
{{- end }}
{{- end }}

{{/*
Entries of a map at a dotted path, keys matched without case like the runtime decoder, as a JSON
list of {path, value}. Takes a dict with map, path (a list) and at, the prefix of the reported paths.
*/}}
{{- define "falcosidekick.foldLookup" -}}
{{- $found := list }}
{{- $first := lower (first .path) }}
{{- range $key, $value := .map }}
{{- if eq (lower $key) $first }}
{{- $at := ternary $key (printf "%s.%s" $.at $key) (eq $.at "") }}
{{- if eq (len $.path) 1 }}
{{- $found = append $found (dict "path" $at "value" $value) }}
{{- else if kindIs "map" $value }}
{{- $found = concat $found (include "falcosidekick.foldLookup" (dict "map" $value "path" (rest $.path) "at" $at) | fromJsonArray) }}
{{- end }}
{{- end }}
{{- end }}
{{- toJson $found }}
{{- end }}

{{/*
Credentials written in the values, which would land in a ConfigMap or the Deployment, as a JSON list
of messages naming the key, never the value. The secret fields of each output come from
files/secret-fields.yaml, generated from the output schemas.
*/}}
{{- define "falcosidekick.inlineSecrets" -}}
{{- $errs := list }}
{{- $schema := .Files.Get "files/secret-fields.yaml" | fromYaml }}
{{- range $name, $cfg := (.Values.outputs | default dict) }}
{{- $secrets := get $schema $name }}
{{- if and $secrets (kindIs "map" $cfg) }}
{{- range $field := ($secrets.fields | default list) }}
{{- $leaf := last (splitList "." $field) }}
{{- range (include "falcosidekick.foldLookup" (dict "map" $cfg "path" (splitList "." $field) "at" (printf "outputs.%s" $name)) | fromJsonArray) }}
{{- if include "falcosidekick.isSet" .value }}
{{- $errs = append $errs (printf "%s: credentials cannot be written in values: put them in a Secret listed in secrets and set %s_file" .path $leaf) }}
{{- end }}
{{- end }}
{{- end }}
{{- range $field, $props := ($secrets.entries | default dict) }}
{{- range (include "falcosidekick.foldLookup" (dict "map" $cfg "path" (splitList "." $field) "at" (printf "outputs.%s" $name)) | fromJsonArray) }}
{{- $entriesAt := .path }}
{{- if kindIs "map" .value }}
{{- range $entry, $entryValue := .value }}
{{- if kindIs "map" $entryValue }}
{{- range $prop := $props }}
{{- range (include "falcosidekick.foldLookup" (dict "map" $entryValue "path" (list $prop) "at" (printf "%s.%s" $entriesAt $entry)) | fromJsonArray) }}
{{- if include "falcosidekick.isSet" .value }}
{{- $errs = append $errs (printf "%s: credentials cannot be written in values: put them in a Secret listed in secrets and list their paths in files" .path) }}
{{- end }}
{{- end }}
{{- end }}
{{- else if include "falcosidekick.isSet" $entryValue }}
{{- $errs = append $errs (printf "%s.%s: must be a map of values, secrets and files" $entriesAt $entry) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- range (include "falcosidekick.foldLookup" (dict "map" (.Values.config | default dict) "path" (list "database" "postgres" "password") "at" "config") | fromJsonArray) }}
{{- if include "falcosidekick.isSet" .value }}
{{- $errs = append $errs (printf "%s: credentials cannot be written in values: set database.postgres.passwordSecret" .path) }}
{{- end }}
{{- end }}
{{- range .Values.extraEnv }}
{{- if and (eq (toString .name) "FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD") (include "falcosidekick.isSet" .value) }}
{{- $errs = append $errs "extraEnv FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD: credentials cannot be written in values: set database.postgres.passwordSecret" }}
{{- end }}
{{- end }}
{{- toJson $errs }}
{{- end }}

{{/*
FALCOSIDEKICK_* variables of settings the chart reads to build the pod, the Services and the
outputs; set through extraEnv they would make the process disagree with them.
*/}}
{{- define "falcosidekick.managedEnv" -}}
{{- toJson (list
  "FALCOSIDEKICK_LISTEN_PORT"
  "FALCOSIDEKICK_MANAGEMENT_LISTEN_PORT"
  "FALCOSIDEKICK_MANAGEMENT_LISTEN_ADDRESS"
  "FALCOSIDEKICK_SHUTDOWN_DELAY"
  "FALCOSIDEKICK_TLS_ENABLED"
  "FALCOSIDEKICK_TLS_MUTUAL_TLS"
  "FALCOSIDEKICK_TLS_CERT_FILE"
  "FALCOSIDEKICK_TLS_KEY_FILE"
  "FALCOSIDEKICK_TLS_CA_FILE"
  "FALCOSIDEKICK_DATABASE_BACKEND"
  "FALCOSIDEKICK_DATABASE_CONNECT_TIMEOUT"
  "FALCOSIDEKICK_DATABASE_SQLITE_PATH"
  "FALCOSIDEKICK_DATABASE_POSTGRES_PASSWORD_FILE"
  "FALCOSIDEKICK_UI_ENABLED"
  "FALCOSIDEKICK_UI_EVENT_SOURCE"
  "FALCOSIDEKICK_API_SECRET_DIRS") }}
{{- end }}

{{/*
Refuses values the chart cannot deploy, with every problem in one message.
*/}}
{{- define "falcosidekick.validate" -}}
{{- $errs := list }}
{{- $config := .Values.config | default dict }}
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
{{- $errs = append $errs "database.backend sqlite supports replicaCount 1 only: the sqlite file belongs to one process; use database.backend postgres to run several replicas" }}
{{- end }}
{{- $errs = concat $errs (include "falcosidekick.inlineSecrets" . | fromJsonArray) }}

{{- /* TLS */}}
{{- $tls := get $config "tls" | default dict }}
{{- if not (kindIs "map" $tls) }}
{{- $tls = dict }}
{{- end }}
{{- if $tls.enabled }}
{{- if and (not .Values.tls.secretName) (not (and $tls.cert_file $tls.key_file)) }}
{{- $errs = append $errs "config.tls.enabled needs tls.secretName, or both config.tls.cert_file and config.tls.key_file" }}
{{- end }}
{{- if and $tls.mutual_tls (not .Values.tls.secretName) (not $tls.ca_file) }}
{{- $errs = append $errs "config.tls.mutual_tls needs a CA: set tls.secretName to a Secret holding ca.crt, or config.tls.ca_file" }}
{{- end }}
{{- else }}
{{- if .Values.tls.secretName }}
{{- $errs = append $errs "tls.secretName is set but config.tls.enabled is not true" }}
{{- end }}
{{- if $tls.mutual_tls }}
{{- $errs = append $errs "config.tls.mutual_tls needs config.tls.enabled" }}
{{- end }}
{{- end }}

{{- /* Database */}}
{{- $database := get $config "database" | default dict }}
{{- if not (kindIs "map" $database) }}
{{- $database = dict }}
{{- end }}
{{- if and (hasKey $database "backend") (ne (toString $database.backend) .Values.database.backend) }}
{{- $errs = append $errs (printf "config.database.backend %q contradicts database.backend %q: set database.backend only" (toString $database.backend) .Values.database.backend) }}
{{- end }}
{{- $sqlite := get $database "sqlite" | default dict }}
{{- if and (eq .Values.database.backend "sqlite") (kindIs "map" $sqlite) (hasKey $sqlite "path") (ne (toString $sqlite.path) "/var/lib/falcosidekick/sidekick.db") }}
{{- $errs = append $errs "config.database.sqlite.path contradicts the volume the chart mounts: remove it, the chart sets /var/lib/falcosidekick/sidekick.db" }}
{{- end }}
{{- if eq .Values.database.backend "postgres" }}
{{- $postgres := get $database "postgres" | default dict }}
{{- if not (kindIs "map" $postgres) }}
{{- $postgres = dict }}
{{- end }}
{{- range $key := list "host" "database" "user" }}
{{- if not (get $postgres $key) }}
{{- $errs = append $errs (printf "database.backend postgres needs config.database.postgres.%s" $key) }}
{{- end }}
{{- end }}
{{- $secretName := .Values.database.postgres.passwordSecret.name }}
{{- if and $secretName $postgres.password_file }}
{{- $errs = append $errs "database.postgres.passwordSecret.name and config.database.postgres.password_file are both set: keep one" }}
{{- else if not (or $secretName $postgres.password_file) }}
{{- $errs = append $errs "database.backend postgres needs a password: set database.postgres.passwordSecret.name, or config.database.postgres.password_file to a file in secrets" }}
{{- end }}
{{- if and $secretName (not .Values.database.postgres.passwordSecret.key) }}
{{- $errs = append $errs "database.postgres.passwordSecret.key is required" }}
{{- end }}
{{- end }}

{{- /* Settings the chart manages */}}
{{- $ui := get $config "ui" | default dict }}
{{- if and (kindIs "map" $ui) (hasKey $ui "enabled") (ne (toString $ui.enabled) (toString .Values.ui.enabled)) }}
{{- $errs = append $errs (printf "config.ui.enabled %v contradicts ui.enabled %v: set ui.enabled only" $ui.enabled .Values.ui.enabled) }}
{{- end }}
{{- $management := get $config "management" | default dict }}
{{- if and .Values.management.service.enabled (kindIs "map" $management) (hasKey $management "listen_address") (ne (toString $management.listen_address) "::") }}
{{- $errs = append $errs (printf "config.management.listen_address %q contradicts management.service.enabled, which listens on \"::\": remove it" (toString $management.listen_address)) }}
{{- end }}
{{- $managedEnv := include "falcosidekick.managedEnv" . | fromJsonArray }}
{{- range .Values.extraEnv }}
{{- if has (toString .name) $managedEnv }}
{{- $errs = append $errs (printf "extraEnv %s: the chart reads this setting from config; set it there" .name) }}
{{- end }}
{{- end }}

{{- /* Service account and outputs */}}
{{- if and .Values.rbac.policyReport (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) }}
{{- $errs = append $errs "rbac.policyReport with serviceAccount.create=false needs serviceAccount.name, the account to bind" }}
{{- end }}
{{- $extraNames := list }}
{{- range $i, $cm := .Values.extraOutputConfigMaps }}
{{- if not (and (kindIs "map" $cm) $cm.name) }}
{{- $errs = append $errs (printf "extraOutputConfigMaps[%d].name is required" $i) }}
{{- else if has $cm.name $extraNames }}
{{- $errs = append $errs (printf "extraOutputConfigMaps: %q is listed twice" $cm.name) }}
{{- else }}
{{- $extraNames = append $extraNames $cm.name }}
{{- end }}
{{- end }}
{{- $pdb := .Values.podDisruptionBudget }}
{{- if and $pdb.enabled (not (include "falcosidekick.isGiven" $pdb.minAvailable)) (not (include "falcosidekick.isGiven" $pdb.maxUnavailable)) }}
{{- $errs = append $errs "podDisruptionBudget needs minAvailable or maxUnavailable" }}
{{- end }}
{{- if $errs }}
{{- fail (printf "\n%s" (join "\n" $errs)) }}
{{- end }}
{{- end }}

{{/*
Whether a value is given: 0 is, an empty string or null is not. Renders "true" or nothing.
*/}}
{{- define "falcosidekick.isGiven" -}}
{{- if not (or (kindIs "invalid" .) (eq (toString .) "")) }}true{{ end }}
{{- end }}

{{- define "falcosidekick.secretDir" -}}
/etc/falcosidekick/secrets/{{ . }}
{{- end }}

{{- define "falcosidekick.extraOutputsDir" -}}
/etc/falcosidekick/outputs/{{ . }}
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
Seconds of a Go duration, with the grammar of time.ParseDuration (5s, 1m30s, .5s, 1.5h, 300us,
300µs), or of a number of nanoseconds. Takes a dict with key, the setting named in the error, and value.
*/}}
{{- define "falcosidekick.durationSeconds" -}}
{{- $value := .value }}
{{- $seconds := 0.0 }}
{{- if kindIs "string" $value }}
{{- if not (regexMatch "^\\+?(0|(([0-9]+(\\.[0-9]*)?|\\.[0-9]+)(ns|us|µs|μs|ms|s|m|h))+)$" $value) }}
{{- fail (printf "%s %q is not a duration such as 5s or 1m30s" .key $value) }}
{{- end }}
{{- $units := dict "h" 3600.0 "m" 60.0 "s" 1.0 "ms" 0.001 "us" 0.000001 "µs" 0.000001 "μs" 0.000001 "ns" 0.000000001 }}
{{- range regexFindAll "([0-9]+(\\.[0-9]*)?|\\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)" $value -1 }}
{{- $number := regexFind "^[0-9.]+" . }}
{{- $seconds = addf $seconds (mulf (float64 $number) (get $units (trimPrefix $number .))) }}
{{- end }}
{{- else if $value }}
{{- if lt (float64 $value) 0.0 }}
{{- fail (printf "%s %v must not be negative" .key $value) }}
{{- end }}
{{- $seconds = divf (float64 $value) 1000000000.0 }}
{{- end }}
{{- $seconds }}
{{- end }}

{{/*
shutdown_delay, plus the 10s the process gives the server and the outputs to drain, plus 5s of margin.
*/}}
{{- define "falcosidekick.terminationGracePeriodSeconds" -}}
{{- $cfg := include "falcosidekick.sidekickConfig" . | fromYaml }}
{{- $delay := hasKey $cfg "shutdown_delay" | ternary $cfg.shutdown_delay "5s" }}
{{- add (ceil (float64 (include "falcosidekick.durationSeconds" (dict "key" "config.shutdown_delay" "value" $delay)))) 15 }}
{{- end }}

{{/*
startupProbe failureThreshold: probes.startup.failureThreshold when set, else enough periods to
cover database.connect_timeout (30s by default), during which the process retries the database
before it listens, plus 30s for the migrations and the outputs to start.
*/}}
{{- define "falcosidekick.startupFailureThreshold" -}}
{{- $startup := .Values.probes.startup }}
{{- if include "falcosidekick.isGiven" $startup.failureThreshold }}
{{- $startup.failureThreshold }}
{{- else }}
{{- $cfg := include "falcosidekick.sidekickConfig" . | fromYaml }}
{{- $timeout := dig "database" "connect_timeout" "30s" $cfg }}
{{- $budget := addf (float64 (include "falcosidekick.durationSeconds" (dict "key" "config.database.connect_timeout" "value" $timeout))) 30.0 }}
{{- ceil (divf $budget (float64 $startup.periodSeconds)) | int }}
{{- end }}
{{- end }}

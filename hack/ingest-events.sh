#!/usr/bin/env bash
#
# Ingest N random Falco-shaped events into a falcosidekick instance by POSTing
# to its root endpoint. Intended for local UI / dashboard load testing.
#
# Usage:
#   hack/ingest-events.sh [options]
#
# Options:
#   -n COUNT      number of events to send (default: 1000)
#   -u URL        falcosidekick POST URL (default: http://localhost:2801/)
#   -c PAR        parallel worker processes (default: 20)
#   -w SECONDS    spread events over the last N seconds (default: 86400 = 24h)
#   -q            quiet mode (no per-request progress)
#   -h            print help
#
# Examples:
#   hack/ingest-events.sh -n 10000                      # 10k events over last 24h
#   hack/ingest-events.sh -n 500 -w 300                 # 500 events in last 5m (storm)
#   hack/ingest-events.sh -u http://localhost:28010/    # custom port-forward port

set -euo pipefail

COUNT=1000
URL="http://localhost:2801/"
PAR=20
WINDOW=86400
QUIET=0

while getopts ":n:u:c:w:qh" opt; do
  case "$opt" in
    n) COUNT="$OPTARG" ;;
    u) URL="$OPTARG" ;;
    c) PAR="$OPTARG" ;;
    w) WINDOW="$OPTARG" ;;
    q) QUIET=1 ;;
    h) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//;s/^#//' ; exit 0 ;;
    *) echo "unknown option -$OPTARG" >&2 ; exit 2 ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }

# Strip trailing slash for healthz probe
BASE="${URL%/}"
if ! curl -sf --max-time 3 "${BASE}/healthz" >/dev/null 2>&1; then
  echo "[ingest] falcosidekick not reachable at ${BASE}/healthz" >&2
  echo "[ingest] start the backend or port-forward first (see hack/ui-dev-cluster.sh)" >&2
  exit 1
fi

# The emitter is exported as an env-visible function. xargs spawns bash -c and
# invokes it per event; RANDOM is re-seeded per subshell so each event is unique.
# shellcheck disable=SC2329 # invoked through xargs and export -f
emit_event() {
  # Rule catalog: rule|source|tag1,tag2
  local rules=(
    "Read sensitive file untrusted|syscall|filesystem,mitre_credential_access"
    "Write below /etc|syscall|filesystem,mitre_persistence"
    "Write below root|syscall|filesystem,mitre_persistence"
    "Container drift detected (open+create)|syscall|container,drift,process"
    "Terminal shell in container|syscall|shell,mitre_execution"
    "Launch Suspicious Network Tool in Container|syscall|network,process"
    "Outbound connection to C2 server|syscall|network,mitre_command_and_control"
    "Modify binary dirs|syscall|filesystem,mitre_persistence"
    "Create files below dev|syscall|filesystem,mitre_defense_evasion"
    "Clear log activities|syscall|logs,mitre_defense_evasion"
    "Sudo potential privilege escalation|syscall|users,mitre_privilege_escalation"
    "Run shell untrusted|syscall|shell,users"
    "Execution from /dev/shm|syscall|filesystem,mitre_execution"
    "Drop and execute new binary|syscall|process,mitre_persistence"
    "Launch Package Management Process in Container|syscall|process,software_mgmt"
    "DB program spawned process|syscall|database,process,mitre_execution"
    "Netcat Remote Code Execution in Container|syscall|network,process,mitre_execution"
    "Change thread namespace|syscall|process,container,mitre_privilege_escalation"
    "Write below binary dir|syscall|filesystem,mitre_persistence"
    "Read ssh information|syscall|filesystem,mitre_credential_access"
    "Find privilege escalation|syscall|process,mitre_privilege_escalation"
    "Launch disallowed container|syscall|container,mitre_execution"
    "Disallowed K8s user|k8s_audit|k8s,mitre_persistence"
    "Kubernetes: exec into pod|k8s_audit|k8s,mitre_execution"
    "Kubernetes: create config map with secret|k8s_audit|k8s,mitre_credential_access"
    "Kubernetes: attach to pod|k8s_audit|k8s,mitre_execution"
    "Kubernetes: delete namespace|k8s_audit|k8s,mitre_impact"
    "Kubernetes: create privileged pod|k8s_audit|k8s,container,mitre_privilege_escalation"
    "Kubernetes: port-forward to pod|k8s_audit|k8s,mitre_execution"
  )
  local hosts=("worker-1" "worker-2" "worker-3" "worker-4" "worker-5" "control-plane-1" "control-plane-2" "edge-gw-1" "ingress-gw" "db-primary")
  local procs=("bash" "curl" "nmap" "nc" "wget" "python3" "node" "nginx" "sh" "kubectl" "cat" "apt" "ssh" "systemd" "cron" "docker" "containerd" "runc" "sed" "awk")
  local containers=("nginx-prod" "api-gw" "redis-cache" "postgres-primary" "kafka-broker-0" "worker-pool" "ingest-etl" "falco-test" "prometheus" "grafana" "loki" "vault")
  local users=("root" "app" "www-data" "admin" "ubuntu" "nobody" "postgres" "redis")

  local window="${WINDOW:-86400}"
  local url="${URL:-http://localhost:2801/}"

  # Re-seed RANDOM per subshell so parallel workers don't collide.
  # Bash already seeds $RANDOM per subshell; adding $$ + iteration keeps it
  # stable under fast xargs spawn loops. Avoid date +%N (BSD-only + leading
  # zeros trip bash's base-10 parser).
  RANDOM=$((RANDOM + $$ + ${1:-0}))

  # Pick weighted priority. Rare emergency/alert/critical, mostly warning/notice/info.
  local r=$((RANDOM % 1000))
  local priority
  if   (( r < 2   )); then priority="emergency"
  elif (( r < 10  )); then priority="alert"
  elif (( r < 30  )); then priority="critical"
  elif (( r < 90  )); then priority="error"
  elif (( r < 330 )); then priority="warning"
  elif (( r < 600 )); then priority="notice"
  elif (( r < 910 )); then priority="informational"
  else priority="debug"
  fi

  local idx=$((RANDOM % ${#rules[@]}))
  local rule_spec="${rules[$idx]}"
  local rule="${rule_spec%%|*}"
  rule_spec="${rule_spec#*|}"
  local source="${rule_spec%%|*}"
  local tags_csv="${rule_spec#*|}"

  local host="${hosts[$((RANDOM % ${#hosts[@]}))]}"
  local proc="${procs[$((RANDOM % ${#procs[@]}))]}"
  local cont="${containers[$((RANDOM % ${#containers[@]}))]}"
  local user="${users[$((RANDOM % ${#users[@]}))]}"

  # Random offset in the past $window seconds
  local offset=$((RANDOM * window / 32767))
  # macOS date syntax (BSD); falls back to plain now on Linux coreutils.
  local ts
  ts=$(date -u -v-"${offset}"S +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null \
       || date -u -d "@$(( $(date +%s) - offset ))" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null \
       || date -u +%Y-%m-%dT%H:%M:%S.000Z)

  local pid=$((RANDOM + 1000))

  # Comma-separated tags -> JSON array
  local tags_json='['
  local first=1
  local IFS=','
  for t in $tags_csv; do
    if (( first == 0 )); then tags_json+=','; fi
    tags_json+="\"$t\""
    first=0
  done
  tags_json+=']'
  unset IFS

  # Escape quotes in string fields defensively.
  local rule_esc="${rule//\"/\\\"}"

  local body
  body="{\"time\":\"$ts\",\"rule\":\"$rule_esc\",\"output\":\"Triggered rule=$rule_esc proc=$proc user=$user host=$host container=$cont\",\"source\":\"$source\",\"priority\":\"$priority\",\"hostname\":\"$host\",\"tags\":$tags_json,\"output_fields\":{\"proc.name\":\"$proc\",\"proc.pid\":$pid,\"user.name\":\"$user\",\"container.name\":\"$cont\",\"evt.type\":\"execve\"}}"

  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST -H 'Content-Type: application/json' \
    -d "$body" \
    "$url" 2>/dev/null || echo "000")
  echo "$code"
}

export -f emit_event
export URL WINDOW

START_TS=$(date +%s)
echo "[ingest] posting $COUNT events to $URL (parallel=$PAR, window=${WINDOW}s)"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

seq 1 "$COUNT" | xargs -n 1 -P "$PAR" -I {} bash -c 'emit_event "$@"' _ {} > "$TMP"

ok=$(grep -c '^200$' "$TMP" || true)
fail=$((COUNT - ok))
elapsed=$(( $(date +%s) - START_TS ))
if (( elapsed < 1 )); then elapsed=1; fi
rate=$(( COUNT / elapsed ))

echo ""
echo "[ingest] done in ${elapsed}s  ok=${ok}  fail=${fail}  rate=${rate}/s"
echo ""

# The summary below is informational and must not decide the exit status.
set +e

if (( QUIET == 0 )); then

if command -v python3 >/dev/null 2>&1; then
  echo "==> pipeline/status:"
  curl -s "${BASE}/api/v1/pipeline/status" | python3 -c 'import json,sys
try:
  d = json.load(sys.stdin)
  for o in d.get("outputs", []):
    name = o["name"]; status = o.get("status","?"); sent = o["sent_total"]; failed = o["failed_total"]
    print("  {:15s} status={:8s} sent={:>7} failed={}".format(name, status, sent, failed))
except Exception as e:
  print("  (unable to parse status: " + str(e) + ")")'
  echo ""
  echo "==> total events in store:"
  curl -s "${BASE}/api/v1/events/count" | python3 -c 'import json,sys
try:
  print("  " + str(json.load(sys.stdin).get("count",0)) + " events")
except Exception:
  print("  (unable)")'
  echo ""
  echo "==> by priority (last 24h):"
  curl -s "${BASE}/api/v1/events/count/priority?since=24h" | python3 -c 'import json,sys
try:
  g = json.load(sys.stdin).get("groups",{}) or {}
  for k,v in sorted(g.items(), key=lambda x: -x[1]):
    print("  {:14s} {}".format(k, v))
except Exception:
  print("  (unable)")'
  echo ""
  echo "==> timestamp spread (most recent 5000 events):"
  curl -s "${BASE}/api/v1/events/search?limit=5000&sort_by=timestamp&sort_desc=true" \
    | WINDOW="$WINDOW" python3 -c '
import json, os, sys
from datetime import datetime, timezone
try:
  data = json.load(sys.stdin).get("events", [])
  if not data:
    print("  (empty)"); sys.exit(0)
  now = datetime.now(timezone.utc)
  ages = []
  for e in data:
    try:
      t = datetime.fromisoformat(e["time"].replace("Z", "+00:00"))
      ages.append((now - t).total_seconds() / 60.0)
    except Exception:
      pass
  if not ages:
    print("  (no parseable timestamps)"); sys.exit(0)
  requested_min = float(os.environ.get("WINDOW", 86400)) / 60.0
  print("  requested window: {:.1f} min".format(requested_min))
  print("  sample size:      {}".format(len(ages)))
  print("  oldest:           {:.1f} min ago".format(max(ages)))
  print("  newest:           {:.1f} min ago".format(min(ages)))
  buckets = 10
  step = requested_min / buckets
  counts = [0] * buckets
  for a in ages:
    idx = min(buckets - 1, int(a // step)) if step > 0 else 0
    if idx >= 0:
      counts[idx] += 1
  peak = max(counts) if counts else 1
  print("  distribution ({} buckets of {:.1f} min, newest first):".format(buckets, step))
  for i, c in enumerate(counts):
    bar = "#" * int(c * 32 / max(1, peak))
    print("    [{:6.1f} .. {:6.1f} min ago] {:5d} {}".format(i*step, (i+1)*step, c, bar))
except Exception as e:
  print("  (unable: " + str(e) + ")")'
fi
fi

if (( fail > 0 )); then
  echo "[ingest] ${fail} of ${COUNT} events failed" >&2
  exit 1
fi
exit 0

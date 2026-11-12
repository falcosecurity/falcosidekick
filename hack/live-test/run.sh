#!/usr/bin/env bash
set -euo pipefail

# Live-test protocol for falcosidekick against a local kind cluster.
# See README.md in this directory for the criteria.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hack/lib/cluster.sh
source "$HERE/../lib/cluster.sh"
NAMESPACE="$HELPER_NAMESPACE"
IMAGE="${FSK_IMAGE:-falcosidekick}:${FSK_TAG:-local}"
# RUN_ID marks this run's events, so checks match what this run sent, not any delivery.
RUN_ID="live-test-$$-$(date +%s)"
TRIGGER_POD="live-test-trigger-$$"
# The Component is applied with the image under test, not the one written in the manifest.
RENDER_DIR="$(mktemp -d)"
sed "s|image: falcosidekick:local|image: $IMAGE|" "$HERE/component.yaml" > "$RENDER_DIR/component.yaml"
MANIFESTS=("$HERE/webhook-receiver.yaml" "$RENDER_DIR/component.yaml")
LOCAL_PORT="${FSK_LOCAL_PORT:-28010}"
MGMT_LOCAL_PORT="${FSK_MGMT_LOCAL_PORT:-28020}"
TIMEOUT_READY="${FSK_TIMEOUT_READY:-90s}"
FALCO_PROPAGATION_WAIT="${FSK_FALCO_WAIT:-30}"
WEBHOOK_WAIT="${FSK_WEBHOOK_WAIT:-8}"

FAIL=0
PF_PID=""
MGMT_PF_PID=""

log()  { printf '[live-test] %s\n' "$*"; }
fail() { printf '[live-test][FAIL] %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

cleanup() {
  for pid in "$PF_PID" "$MGMT_PF_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ "$HELPER_APPLIED" -eq 1 ]]; then
    log "teardown: deleting resources owned by this helper"
    kctl -n default delete pod "$TRIGGER_POD" --ignore-not-found >/dev/null 2>&1 || true
  fi
  teardown_owned
  rm -rf "$RENDER_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require() { command -v "$1" >/dev/null 2>&1 || { fail "missing required binary: $1"; exit 1; }; }
require kubectl
require kind
require docker

KIND_CLUSTER="$(resolve_cluster "${FSK_KIND_CLUSTER:-}")" || { fail "set FSK_KIND_CLUSTER to select the cluster"; exit 1; }
use_cluster "$KIND_CLUSTER"

log "1/9 cluster reachable? (context $HELPER_CONTEXT)"
kctl cluster-info >/dev/null || { fail "no cluster reachable (context $HELPER_CONTEXT)"; exit 1; }
require_owned "${MANIFESTS[@]}" || { fail "existing resources are not owned by this helper"; exit 1; }

log "2/9 loading image $IMAGE into kind cluster '$KIND_CLUSTER'"
kind load docker-image --name "$KIND_CLUSTER" "$IMAGE" >/dev/null \
  || { fail "kind load docker-image failed (cluster: $KIND_CLUSTER). Build it first via 'make image'"; exit 1; }

log "3/9 applying webhook-receiver + Component CR"
apply_owned "${MANIFESTS[@]}"

log "4/9 waiting for webhook-receiver + falcosidekick to be Ready (timeout $TIMEOUT_READY)"
kctl -n "$NAMESPACE" rollout status deployment/webhook-receiver --timeout="$TIMEOUT_READY" \
  || { fail "webhook-receiver did not become Ready"; exit 1; }

# The operator creates the Deployment asynchronously, so the pod may not exist yet.
sidekick_deadline=$(( $(date +%s) + ${TIMEOUT_READY%s} ))
while true; do
  if kctl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=falcosidekick 2>/dev/null | grep -q falcosidekick; then
    break
  fi
  if [[ $(date +%s) -gt $sidekick_deadline ]]; then
    fail "falcosidekick pod never appeared within ${TIMEOUT_READY} (operator did not reconcile Component CR)"
    exit 1
  fi
  sleep 2
done
kctl -n "$NAMESPACE" wait --for=condition=Ready pod -l app.kubernetes.io/name=falcosidekick --timeout="$TIMEOUT_READY" \
  || { fail "falcosidekick pod did not become Ready"; exit 1; }
log "  ok: pod Ready [criterion 1]"

log "5/9 starting port-forward to falcosidekick:2801 -> localhost:$LOCAL_PORT"
kubectl --context "$HELPER_CONTEXT" -n "$NAMESPACE" port-forward svc/falcosidekick "$LOCAL_PORT:2801" >/dev/null 2>&1 &
PF_PID=$!
# The management listener (API, UI) is on the pod loopback, which a pod port-forward reaches.
FSK_POD=$(kctl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=falcosidekick -o jsonpath='{.items[0].metadata.name}')
log "  port-forward to $FSK_POD:2802 (management) -> localhost:$MGMT_LOCAL_PORT"
kubectl --context "$HELPER_CONTEXT" -n "$NAMESPACE" port-forward "pod/$FSK_POD" "$MGMT_LOCAL_PORT:2802" >/dev/null 2>&1 &
MGMT_PF_PID=$!
sleep 2

curl_ok() { curl -fsS --max-time 5 "$@" 2>&1; }

extract_input_total() {
  local body="$1"
  local total=0
  while read -r n; do
    total=$((total + n))
  done < <(echo "$body" | grep -E '^falcosidekick_events_total\{.*source="syscall"' | awk '{print $NF}' | awk -F'.' '{print $1}')
  echo "$total"
}

# webhook_sent_total reads sent_total for the "webhook" output from /api/v1/pipeline/status.
webhook_sent_total() {
  curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/pipeline/status" 2>/dev/null \
    | python3 -c 'import json,sys
try:
  for o in json.load(sys.stdin).get("outputs", []):
    if o.get("name") == "webhook":
      print(o.get("sent_total", 0)); break
  else:
    print(0)
except Exception:
  print(0)'
}

# received reports whether the webhook receiver, which logs every request, got a body containing $1.
received() {
  kctl -n "$NAMESPACE" logs deployment/webhook-receiver --tail=1000 2>/dev/null | grep -qF "$1"
}

log "6/9 HTTP smoke checks"
if body=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/readyz") && [[ "$body" == *'"status":"ready"'* ]]; then
  log "  ok: /readyz [criterion 2]"
else
  fail "/readyz did not return {status:ready}: $body"
fi

if body=$(curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/version") && [[ "$body" == *'"version"'* ]]; then
  log "  ok: /api/v1/version [criterion 3]"
else
  fail "/api/v1/version unexpected: $body"
fi

if body=$(curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/config") && [[ "$body" == *'listen_port'* ]]; then
  log "  ok: /api/v1/config [criterion 4]"
else
  fail "/api/v1/config unexpected: $body"
fi

metrics_before=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/metrics" || echo "")
baseline_total=$(extract_input_total "$metrics_before")
log "  baseline falcosidekick_events_total{source=syscall} = $baseline_total"

webhook_baseline=$(webhook_sent_total)
log "  baseline webhook sent_total = $webhook_baseline"

log "7/9 synthetic POST / event"
payload=$(printf '{"time":"%s","rule":"live-test synthetic","output":"%s synthetic output","source":"syscall","priority":"Warning","hostname":"live-test","tags":["live-test"],"output_fields":{"proc.name":"synthetic"}}' \
  "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$RUN_ID")
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" -d "$payload" \
  "http://127.0.0.1:$LOCAL_PORT/")
if [[ "$status" == "200" ]]; then
  log "  ok: POST / -> 200 [criterion 5a]"
else
  fail "POST / returned HTTP $status"
fi

log "  polling webhook output for up to ${WEBHOOK_WAIT}s"
synthetic_delivered=0
for _ in $(seq 1 "$WEBHOOK_WAIT"); do
  wh_now=$(webhook_sent_total)
  if [[ "$wh_now" -gt "$webhook_baseline" ]] && received "$RUN_ID"; then
    synthetic_delivered=1
    break
  fi
  sleep 1
done
if [[ "$synthetic_delivered" -eq 1 ]]; then
  log "  ok: the receiver got event $RUN_ID (sent_total ${webhook_baseline} -> $(webhook_sent_total)) [criterion 5b]"
else
  fail "the receiver did not get event $RUN_ID within ${WEBHOOK_WAIT}s (sent_total baseline=$webhook_baseline)"
  log "  diagnostic: pipeline status:"
  curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/pipeline/status" 2>&1 | sed 's/^/    /' >&2 || true
fi

log "8/9 real Falco rule trigger (read /etc/shadow in a pod)"
# kubectl run --rm returns only once the pod is gone, and the delivery happens meanwhile:
# the baseline must be taken first.
post_trigger_webhook=$(webhook_sent_total)
log "  webhook sent_total baseline before trigger = $post_trigger_webhook"
kctl run -n default --rm -i --restart=Never --image=alpine:3.22 "$TRIGGER_POD" -- \
    sh -c 'cat /etc/shadow >/dev/null 2>&1 || true' >/dev/null 2>&1 \
  || { fail "kubectl run live-test-trigger failed"; }
log "  triggered; polling for up to ${FALCO_PROPAGATION_WAIT}s"
counter_advanced=0
falco_forwarded=0
after_total=0
for _ in $(seq 1 "$FALCO_PROPAGATION_WAIT"); do
  metrics_after=$(curl_ok "http://127.0.0.1:$LOCAL_PORT/metrics" 2>/dev/null || echo "")
  after_total=$(extract_input_total "$metrics_after")
  if [[ "$after_total" -gt "$baseline_total" ]]; then
    counter_advanced=1
  fi
  wh_now=$(webhook_sent_total)
  # The Falco event names the trigger pod; any other delivery does not count.
  if [[ "$wh_now" -gt "$post_trigger_webhook" ]] && received "$TRIGGER_POD"; then
    falco_forwarded=1
  fi
  if [[ "$counter_advanced" -eq 1 && "$falco_forwarded" -eq 1 ]]; then
    break
  fi
  sleep 1
done

log "  falcosidekick_events_total{source=syscall}: before=$baseline_total after=$after_total"
if [[ "$counter_advanced" -eq 1 ]]; then
  log "  ok: /metrics input counter advanced [criterion 7]"
else
  fail "/metrics input counter did not advance (baseline=$baseline_total, after=$after_total)."
fi

if [[ "$falco_forwarded" -eq 1 ]]; then
  log "  ok: the receiver got the Falco event for $TRIGGER_POD (sent_total ${post_trigger_webhook} -> $(webhook_sent_total)) [criterion 6]"
else
  fail "the receiver did not get the Falco event for $TRIGGER_POD within ${FALCO_PROPAGATION_WAIT}s (sent_total baseline=$post_trigger_webhook)"
  log "  diagnostic: pipeline status:"
  curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/pipeline/status" 2>&1 | sed 's/^/    /' >&2 || true
fi

log "9/10 UI shell (browser-shape request)"
if [[ "$IMAGE" == *-slim ]]; then
  # The slim binary embeds no UI: GET / must answer 404, not a page from somewhere else.
  ui_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$MGMT_LOCAL_PORT/" || true)
  if [[ "$ui_status" == "404" ]]; then
    log "  ok: slim variant serves no UI (GET / -> 404) [criterion 8]"
  else
    fail "slim variant: GET / returned '$ui_status' (expected 404)"
  fi
elif decoded=$(curl -sS --compressed -H "Accept-Encoding: gzip" "http://127.0.0.1:$MGMT_LOCAL_PORT/") && [[ "$decoded" == *'<html'* ]]; then
  log "  ok: GET / with Accept-Encoding returned UI HTML shell [criterion 8]"
else
  fail "GET / with Accept-Encoding did not return decoded HTML"
fi

log "10/10 UI-driven output PUT (updates provisioned webhook under allow_ui_updates=true; next file reload would restore the file version)"
UI_WRITE_WAIT="${FSK_UI_WRITE_WAIT:-10}"
pre_ui_sent="$(webhook_sent_total)"
# A PUT carries the version it was read at; a stale one answers 409.
webhook_version=$(curl_ok "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/pipeline/outputs/webhook" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", 0))' 2>/dev/null || echo 0)
put_resp=$(curl -sS -w '\n%{http_code}' -X PUT \
  -H "Content-Type: application/json" \
  -d "{\"version\":${webhook_version},\"config\":{\"method\":\"POST\"}}" \
  "http://127.0.0.1:$MGMT_LOCAL_PORT/api/v1/pipeline/outputs/webhook" || true)
status=$(echo "$put_resp" | tail -n1)
if [[ "$status" == "200" ]]; then
  log "  ok: PUT /api/v1/pipeline/outputs/webhook -> 200 [criterion 9a]"
  start_ts=$(date +%s)
  while :; do
    sleep 1
    probe_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      -d "$(printf '{"time":"%s","output":"ui-apply-probe","priority":"Error","rule":"ui-apply","source":"test","output_fields":{"proc.name":"probe"}}' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)")" \
      "http://127.0.0.1:$LOCAL_PORT/" 2>/dev/null || true)
    if [[ "$probe_status" != "200" ]]; then
      fail "UI apply probe event returned '$probe_status' (expected 200)"
      break
    fi
    new_sent="$(webhook_sent_total)"
    if [[ "$new_sent" -gt "$pre_ui_sent" ]]; then
      log "  ok: UI-updated webhook output delivered events (sent_total ${pre_ui_sent} -> ${new_sent}) [criterion 9b]"
      break
    fi
    if (( $(date +%s) - start_ts >= UI_WRITE_WAIT )); then
      fail "UI-updated webhook output did not deliver any event within ${UI_WRITE_WAIT}s (baseline=${pre_ui_sent})"
      break
    fi
  done
else
  fail "PUT /api/v1/pipeline/outputs/webhook returned '$status' (expected 200)"
fi

if [[ "$FAIL" -gt 0 ]]; then
  printf '[live-test] FAILED with %d criteria unmet\n' "$FAIL" >&2
  exit 1
fi
log "live-test PASSED"

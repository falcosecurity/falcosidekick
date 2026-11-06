#!/usr/bin/env bash
#
# One-shot dev loop: build the UI image, load it into a kind cluster,
# deploy falcosidekick via the falco-operator Component CR (same manifests
# the live-test uses), port-forward the service, and start `bun run dev`
# with FALCOSIDEKICK_BACKEND pointing at the forward.
#
# It acts only on the selected kind cluster and stops if the manifests target
# resources it does not own. On exit (Ctrl-C / dev-server quit) the dev server and
# port-forward are stopped. Cluster resources stay deployed for fast iteration.
#
# Usage:
#   ./hack/ui-dev-cluster.sh [options]
#
# Options:
#   -l PORT         local port for port-forward (default: 2802)
#   -p PORT         management port in the pod (default: 2802)
#   -k NAME         kind cluster name (default: auto-detect single cluster)
#   --skip-build    reuse existing :local image; skip build + kind load
#   --skip-deploy   do not apply webhook-receiver/Component CR (reuse deployed)
#   --clean         on exit, delete the resources this run applied
#   -h, --help      print this help

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck source=hack/lib/cluster.sh
source "$HERE/lib/cluster.sh"
NAMESPACE="$HELPER_NAMESPACE"
MANIFESTS=("$HERE/live-test/webhook-receiver.yaml" "$HERE/live-test/component.yaml")

CLEAN_ON_EXIT=0
SKIP_BUILD=0
SKIP_DEPLOY=0
SERVICE="falcosidekick"
LOCAL_PORT="2802"
BACKEND_PORT="2802"
CLUSTER=""
IMAGE="${FSK_IMAGE:-falcosidekick}:${FSK_TAG:-local}"

usage() { sed -n '1,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) LOCAL_PORT="$2"; shift 2;;
    -p) BACKEND_PORT="$2"; shift 2;;
    -k) CLUSTER="$2"; shift 2;;
    --skip-build) SKIP_BUILD=1; shift;;
    --skip-deploy) SKIP_DEPLOY=1; shift;;
    --clean) CLEAN_ON_EXIT=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2;;
  esac
done

log() { printf '\033[1;36m[dev-cluster]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[dev-cluster][ERR]\033[0m %s\n' "$*" >&2; }

for tool in kubectl kind docker bun make curl; do
  command -v "$tool" >/dev/null 2>&1 || { err "missing required tool: $tool"; exit 1; }
done

CLUSTER="$(resolve_cluster "$CLUSTER")" || { err "pass -k <cluster>"; exit 1; }
use_cluster "$CLUSTER"

kctl cluster-info >/dev/null 2>&1 || { err "no cluster reachable via $HELPER_CONTEXT"; exit 1; }
require_owned "${MANIFESTS[@]}" || exit 1

PF_PID=""
DEV_PID=""
PF_LOG="$(mktemp)"

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  echo ""
  stop_child "$DEV_PID"
  if [[ -n "$PF_PID" ]]; then
    log "stopping port-forward"
  fi
  stop_child "$PF_PID"
  rm -f "$PF_LOG"
  if [[ $CLEAN_ON_EXIT -eq 1 ]]; then
    log "--clean: deleting resources applied by this run"
    teardown_owned
  else
    log "cluster resources left in place (pass --clean to tear down)"
  fi
}

# shellcheck disable=SC2329 # invoked by cleanup
stop_child() {
  if [[ -n "$1" ]] && kill -0 "$1" 2>/dev/null; then
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "kind cluster: $CLUSTER"
log "namespace:    $NAMESPACE"
log "image:        $IMAGE"

if [[ $SKIP_BUILD -eq 0 ]]; then
  log "step 1/5  build UI image"
  (cd "$REPO" && make image)
else
  log "step 1/5  skipped build (--skip-build)"
fi

log "step 2/5  load image into kind cluster '$CLUSTER'"
kind load docker-image --name "$CLUSTER" "$IMAGE"

if [[ $SKIP_DEPLOY -eq 0 ]]; then
  log "step 3/5  apply webhook-receiver + Component CR"
  apply_owned "${MANIFESTS[@]}"
else
  log "step 3/5  skipped deploy (--skip-deploy)"
fi

log "step 4/5  wait for operator to reconcile deployment/$SERVICE"
deadline=$(( $(date +%s) + 90 ))
while true; do
  if kctl -n "$NAMESPACE" get "deployment/$SERVICE" >/dev/null 2>&1; then
    break
  fi
  if [[ $(date +%s) -gt $deadline ]]; then
    err "deployment/$SERVICE never appeared (operator did not reconcile Component CR within 90s)"
    exit 1
  fi
  sleep 2
done

log "          rollout restart deployment/$SERVICE to pick up the freshly loaded image"
kctl -n "$NAMESPACE" rollout restart "deployment/$SERVICE" >/dev/null 2>&1 || true

log "          wait for webhook-receiver + $SERVICE Ready"
kctl -n "$NAMESPACE" rollout status deployment/webhook-receiver --timeout=90s || {
  err "webhook-receiver did not become Ready"
  exit 1
}
kctl -n "$NAMESPACE" rollout status "deployment/$SERVICE" --timeout=120s || {
  err "deployment/$SERVICE did not become Ready"
  kctl -n "$NAMESPACE" describe "deployment/$SERVICE" | tail -60 >&2 || true
  exit 1
}

# The API listens on the pod loopback; a deployment port-forward reaches it, the Service does not.
log "step 5/5  port-forward deployment/$SERVICE:$BACKEND_PORT -> localhost:$LOCAL_PORT"
kubectl --context "$HELPER_CONTEXT" -n "$NAMESPACE" port-forward "deployment/$SERVICE" "$LOCAL_PORT:$BACKEND_PORT" >"$PF_LOG" 2>&1 &
PF_PID=$!

for _ in $(seq 1 20); do
  if curl -sf "http://localhost:$LOCAL_PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sf "http://localhost:$LOCAL_PORT/healthz" >/dev/null 2>&1; then
  err "port-forward did not become reachable on http://localhost:$LOCAL_PORT within 10s"
  tail -n 20 "$PF_LOG" >&2 || true
  exit 1
fi

log "backend reachable at http://localhost:$LOCAL_PORT"
log "starting UI dev server (bun run dev). Press Ctrl+C to stop."
echo ""

# A waited child, not exec: this shell owns the port-forward and teardown.
cd "$REPO/ui"
FALCOSIDEKICK_BACKEND="http://localhost:$LOCAL_PORT" bun run dev &
DEV_PID=$!
dev_status=0
wait "$DEV_PID" || dev_status=$?
DEV_PID=""
exit "$dev_status"

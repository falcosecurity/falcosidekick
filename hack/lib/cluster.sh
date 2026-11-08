#!/usr/bin/env bash
# Shared safety rules for helpers that touch a local kind cluster. Sourced, not run.
#
# Every kubectl call goes through kctl, pinned to the selected kind cluster.
# Only resources carrying HELPER_LABEL are treated as ours: a run stops before any
# mutation if a manifest target exists without it, and teardown deletes by label.

HELPER_NAMESPACE="falco"
HELPER_OWNER="falcosidekick-dev"
HELPER_LABEL="app.kubernetes.io/part-of=$HELPER_OWNER"
HELPER_RESOURCES="configmap,service,deployment,components.instance.falcosecurity.dev"
HELPER_APPLIED=0
HELPER_CONTEXT=""

# resolve_cluster prints the kind cluster to use: the explicit name if it exists,
# or the only cluster present. Anything else is an error, never a guess.
resolve_cluster() {
  local explicit="$1" clusters count
  clusters="$(kind get clusters 2>/dev/null || true)"
  if [[ -n "$explicit" ]]; then
    if ! grep -Fxq -- "$explicit" <<<"$clusters"; then
      echo "kind cluster '$explicit' not found" >&2
      return 1
    fi
    printf '%s\n' "$explicit"
    return 0
  fi
  count="$(grep -c . <<<"$clusters" || true)"
  if [[ "$count" -ne 1 ]]; then
    echo "found $count kind clusters; name one explicitly" >&2
    return 1
  fi
  printf '%s\n' "$clusters"
}

use_cluster() {
  HELPER_CONTEXT="kind-$1"
}

# kctl is a function: backgrounding it yields a subshell PID, so a background
# kubectl that must be stopped later is started directly with HELPER_CONTEXT.
kctl() {
  kubectl --context "$HELPER_CONTEXT" "$@"
}

# require_owned stops unless every existing target of the manifests has our label.
require_owned() {
  local manifest found foreign
  for manifest in "$@"; do
    found="$(kctl get -f "$manifest" --ignore-not-found --no-headers \
      -o 'custom-columns=KIND:.kind,NAME:.metadata.name,OWNER:.metadata.labels.app\.kubernetes\.io/part-of')" || {
      echo "cannot inspect resources of $manifest" >&2
      return 1
    }
    foreign="$(awk -v owner="$HELPER_OWNER" 'NF && $3 != owner {print $1 "/" $2}' <<<"$found")"
    if [[ -n "$foreign" ]]; then
      echo "refusing to touch resources this helper does not own:" >&2
      printf '%s\n' "$foreign" >&2
      return 1
    fi
  done
}

apply_owned() {
  local manifest
  HELPER_APPLIED=1
  for manifest in "$@"; do
    kctl apply -f "$manifest" >/dev/null
  done
}

teardown_owned() {
  if [[ "$HELPER_APPLIED" -eq 1 ]]; then
    kctl -n "$HELPER_NAMESPACE" delete "$HELPER_RESOURCES" -l "$HELPER_LABEL" --ignore-not-found >/dev/null 2>&1 || true
  fi
}

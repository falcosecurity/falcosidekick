#!/usr/bin/env bash
set -euo pipefail

# Runs the Elasticsearch output live tests against each supported server
# version in a disposable local container. Requires Docker.
# Override the list with ES_MATRIX="name=image ..." to test other versions.

ES_MATRIX="${ES_MATRIX:-elasticsearch-7=docker.io/library/elasticsearch:7.17.28 elasticsearch-8=docker.io/library/elasticsearch:8.19.23 elasticsearch-9=docker.io/library/elasticsearch:9.5.5 opensearch-2=docker.io/opensearchproject/opensearch:2.19.7 opensearch-3=docker.io/opensearchproject/opensearch:3.9.0}"
PORT="${ES_MATRIX_PORT:-19201}"
CONTAINER="falcosidekick-es-matrix"
GO="${GO:-go}"
# Elasticsearch runs with security on so the authentication cases run too.
# OpenSearch runs without its security plugin, which requires TLS.
ES_PASSWORD="falcosidekick-matrix"

log() { printf '[es-matrix] %s\n' "$*"; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_ready() {
  for _ in $(seq 1 90); do
    if curl -sf ${auth_args[@]+"${auth_args[@]}"} "http://127.0.0.1:$PORT/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

failed=()
for entry in $ES_MATRIX; do
  name="${entry%%=*}"
  image="${entry#*=}"
  cleanup
  env_args=(-e discovery.type=single-node -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m")
  auth_args=()
  test_env=(FALCOSIDEKICK_ES_URL="http://127.0.0.1:$PORT")
  case "$name" in
    opensearch*) env_args+=(-e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true) ;;
    *)
      env_args+=(-e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=false -e xpack.security.authc.api_key.enabled=true -e "ELASTIC_PASSWORD=$ES_PASSWORD")
      auth_args=(-u "elastic:$ES_PASSWORD")
      test_env+=(FALCOSIDEKICK_ES_USERNAME=elastic FALCOSIDEKICK_ES_PASSWORD="$ES_PASSWORD")
      ;;
  esac
  log "$name: starting $image"
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:9200" "${env_args[@]}" "$image" >/dev/null
  if ! wait_ready; then
    log "$name: server not ready"
    failed+=("$name")
    continue
  fi
  version="$(curl -sf ${auth_args[@]+"${auth_args[@]}"} "http://127.0.0.1:$PORT/" | sed -n 's/.*"number" *: *"\([^"]*\)".*/\1/p' | head -1)"
  log "$name: server $version"
  if env "${test_env[@]}" "$GO" test -count=1 -v -tags elasticsearch_live -run TestLiveElasticsearch ./internal/outputs/elasticsearch/ | grep -E '^(=== RUN|--- |\s+---|PASS|FAIL|ok)|Error|SKIP'; then
    log "$name: PASS ($version)"
  else
    log "$name: FAIL ($version)"
    failed+=("$name")
  fi
done

if ((${#failed[@]} > 0)); then
  log "failed: ${failed[*]}"
  exit 1
fi
log "all passed"

#!/usr/bin/env bash
set -euo pipefail

# Runs the Elasticsearch output live tests against each supported server
# version in a disposable local container. Requires Docker.
# Override the list with ES_MATRIX="name=image ..." to test other versions.
#
# Modes, chosen by name prefix:
#   elasticsearch-7  HTTP, basic auth and API keys
#   elasticsearch-*  HTTPS with the server's generated CA, basic auth and API keys
#   opensearch-*     HTTPS with the demo CA, basic auth and a client certificate

ES_MATRIX="${ES_MATRIX:-elasticsearch-7=docker.io/library/elasticsearch:7.17.28 elasticsearch-8=docker.io/library/elasticsearch:8.19.23 elasticsearch-9=docker.io/library/elasticsearch:9.5.5 opensearch-2=docker.io/opensearchproject/opensearch:2.19.7 opensearch-3=docker.io/opensearchproject/opensearch:3.9.0}"
PORT="${ES_MATRIX_PORT:-19201}"
CONTAINER="falcosidekick-es-matrix"
GO="${GO:-go}"
PASSWORD="Falcosidekick-Matrix-2026!"
WORKDIR="$(mktemp -d)"

log() { printf '[es-matrix] %s\n' "$*"; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap 'cleanup; rm -rf "$WORKDIR"' EXIT

wait_ready() {
  local url="$1" user="$2"
  for _ in $(seq 1 90); do
    if curl -skf -u "$user:$PASSWORD" "$url/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null; then
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
  rm -rf "${WORKDIR:?}"/*
  env_args=(-e discovery.type=single-node -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m")
  test_env=(FALCOSIDEKICK_ES_PASSWORD="$PASSWORD")
  case "$name" in
    elasticsearch-7)
      url="http://127.0.0.1:$PORT"; user="elastic"
      env_args+=(-e xpack.security.enabled=true -e xpack.security.authc.api_key.enabled=true -e "ELASTIC_PASSWORD=$PASSWORD")
      ;;
    elasticsearch-*)
      url="https://127.0.0.1:$PORT"; user="elastic"
      env_args+=(-e "ELASTIC_PASSWORD=$PASSWORD")
      ca_path=/usr/share/elasticsearch/config/certs/http_ca.crt
      ;;
    opensearch-*)
      url="https://127.0.0.1:$PORT"; user="admin"
      env_args+=(-e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=$PASSWORD")
      ca_path=/usr/share/opensearch/config/root-ca.pem
      test_env+=(FALCOSIDEKICK_ES_API_KEYS=false
        FALCOSIDEKICK_ES_CLIENT_CERT="$WORKDIR/client.pem" FALCOSIDEKICK_ES_CLIENT_KEY="$WORKDIR/client-key.pem")
      ;;
    *) log "$name: unknown mode"; failed+=("$name"); continue ;;
  esac
  test_env+=(FALCOSIDEKICK_ES_URL="$url" FALCOSIDEKICK_ES_USERNAME="$user")

  log "$name: starting $image"
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:9200" "${env_args[@]}" "$image" >/dev/null
  if ! wait_ready "$url" "$user"; then
    log "$name: server not ready"
    failed+=("$name")
    continue
  fi
  if [[ "$url" == https://* ]]; then
    docker cp -q "$CONTAINER:$ca_path" "$WORKDIR/ca.pem"
    test_env+=(FALCOSIDEKICK_ES_CA_FILE="$WORKDIR/ca.pem")
    if [[ "$name" == opensearch-* ]]; then
      docker cp -q "$CONTAINER:/usr/share/opensearch/config/kirk.pem" "$WORKDIR/client.pem"
      docker cp -q "$CONTAINER:/usr/share/opensearch/config/kirk-key.pem" "$WORKDIR/client-key.pem"
    fi
  fi
  version="$(curl -skf -u "$user:$PASSWORD" "$url/" | sed -n 's/.*"number" *: *"\([^"]*\)".*/\1/p' | head -1)"
  log "$name: server $version at $url"
  if env "${test_env[@]}" "$GO" test -count=1 -v -tags elasticsearch_live -run TestLiveElasticsearch ./internal/outputs/elasticsearch/ |
    grep -E '^(=== RUN|--- |\s+---|PASS|FAIL|ok)|Error|SKIP|live_test.go'; then
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

# falcosidekick live-test

Deploys a freshly built `falcosidekick` image into a local kind cluster through the falco-operator `Component` CR, verifies end-to-end event flow, and tears everything down.

## Prerequisites

- Local kind cluster up.
- Falco operator installed and reconciling the `Falco` + `Config` + `Plugin` + `Rulesfile` CRs from [`operator-resources.yaml`](operator-resources.yaml). The `Config` CR in that file already forces Falco's HTTP output to `http://falcosidekick.falco.svc:2801`.
- `kubectl` context pointing at the kind cluster.
- Docker running (for `kind load docker-image`).
- Bun installed (via `~/.bun/bin/bun`).

## One-shot run

From the repo root:

```sh
make live-test
```

which expands to:

1. `make image`: builds the UI image for the host arch into the local Docker daemon as `falcosidekick:local`.
2. `./hack/live-test/run.sh`: orchestrates the rest.

Override the image variant with `FSK_TAG=local-slim` (after `make image-slim`) to run against the slim binary. Override the local port with `FSK_LOCAL_PORT=<port>` and the cluster with `FSK_KIND_CLUSTER=<name>`.

## What the script does

1. Verify `kubectl cluster-info` works.
2. `kind load docker-image falcosidekick:local` (loads the image into kind's node cache).
3. `kubectl apply` [`webhook-receiver.yaml`](webhook-receiver.yaml) + [`component.yaml`](component.yaml).
4. Wait for the `webhook-receiver` Deployment and the falcosidekick pod (managed by the operator via the `Component` CR) to become `Ready` (90s timeout).
5. Port-forward `svc/falcosidekick` to `localhost:28010`.
6. HTTP smoke checks: `/healthz`, `/version`, `/api/v1/config`.
7. Synthetic `POST /` event; verify webhook-receiver logs it.
8. Trigger a real Falco rule via `kubectl run ... cat /etc/shadow`; verify falcosidekick logs a matching event.
9. `/metrics` counter > 0; `GET /` returns the UI HTML shell.
10. Teardown (`trap` always runs): delete Component CR + webhook-receiver.

## Success criteria

Every criterion is a hard blocker: any failure exits the script non-zero.

- **1** pod Ready.
- **2** `/healthz` 200 + `{"status":"ok"}`.
- **3** `/version` returns the build metadata JSON.
- **4** `/api/v1/config` returns the provisioned config.
- **5a** synthetic `POST /` returns 200.
- **5b** webhook output's `sent_total` advances after the synthetic POST (observed via `/api/v1/pipeline/status`).
- **6** real Falco rule trigger (`cat /etc/shadow` in an alpine pod) causes the webhook output's `sent_total` to advance again.
- **7** `falcosidekick_input_total{source="syscall"}` metric advances beyond baseline.
- **8** `GET /` with a browser-shape `Accept-Encoding: gzip` returns 200 and decoded HTML (UI-embedded variant only; skipped when `FSK_TAG=local-slim`).
- **9a** `PUT /api/v1/pipeline/outputs/webhook` returns 200.
- **9b** after 9a, posting synthetic events shows the webhook output still delivering (the UI write applied, the output is live in the dispatcher).

## Files

- [`sidekick.yaml`](sidekick.yaml): core config (ConfigMap embeds a copy for the in-cluster deployment; this file is the human-readable reference).
- [`outputs.yaml`](outputs.yaml): output config (inmemory + webhook).
- [`component.yaml`](component.yaml): operator `Component` CR for falcosidekick + its Service + the ConfigMap that holds `sidekick.yaml` + `outputs.yaml`.
- [`webhook-receiver.yaml`](webhook-receiver.yaml): `mendhak/http-https-echo`-based HTTP sink that logs every request body; used as the downstream target for the `webhook` output so the test can observe `sent_total` advancing.
- [`run.sh`](run.sh): orchestration script; re-entrant, self-cleans via `trap`.

## Troubleshooting

- If `kind load docker-image` fails, run `make image` and retry.
- If the pod doesn't become Ready, check `kubectl -n falco describe pod <falcosidekick-pod>` and `kubectl -n falco logs <falcosidekick-pod>`.
- If criterion 6 fails, inspect `kubectl -n falco logs deploy/falco -c falco` for the `Read sensitive file untrusted` rule firing; if Falco logs the rule but falcosidekick never sees it, check the `Config` CR's `http_output.url` and DNS resolution from the Falco pod (`curl http://falcosidekick.falco.svc:2801/healthz` from inside a Falco pod).

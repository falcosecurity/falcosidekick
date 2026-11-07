# Install Falcosidekick v3

Falcosidekick v3 is in beta. It reads two kinds of files:

- one core file (`-c sidekick.yaml`): listener, logging, UI, API, database, runtime defaults;
- one or more output files (`-o outputs.yaml`, repeatable): where events go.

Start from [`config_example_sidekick.yaml`](../config_example_sidekick.yaml) and [`config_example_outputs.yaml`](../config_example_outputs.yaml).

## Images

| Image | Content |
| --- | --- |
| `falcosecurity/falcosidekick:<version>` | binary with the built-in web UI, for example `3.1.2` |
| `falcosecurity/falcosidekick:<version>-slim` | binary without the UI |
| `3.1`, `3`, `v3-latest` (and `-slim`) | latest stable release of that minor, of v3, of v3; not moved by pre-releases |
| `v3-main`, `v3-main-slim` | latest `master` build, not a release |

The same tags are published to `public.ecr.aws/falcosecurity/falcosidekick`. `latest` is still v2.

The container runs as user 1234. It receives Falco events on port 2801, which also serves `/healthz`, `/version` and `/metrics`. The API and the UI are on a separate management port, 2802, bound to `127.0.0.1` by default because the API has no authentication.

## Container

Write a minimal `outputs.yaml`:

```yaml
outputs:
  webhook:
    host: "http://receiver.example:8080"
    endpoint: /falco
```

Run:

```sh
docker run -d --name falcosidekick -p 2801:2801 \
  -v "$PWD/sidekick.yaml:/etc/falcosidekick/sidekick.yaml:ro" \
  -v "$PWD/outputs.yaml:/etc/falcosidekick/outputs.yaml:ro" \
  falcosecurity/falcosidekick:v3-latest \
  -c /etc/falcosidekick/sidekick.yaml -o /etc/falcosidekick/outputs.yaml
```

Check it:

```sh
curl -s localhost:2801/healthz
```

The management port listens on the container's loopback, which `-p` cannot reach. To use the API or the UI from the host, bind it to every container interface and publish it on the host loopback only:

```yaml
# sidekick.yaml
management:
  listen_address: "0.0.0.0"
```

```sh
docker run ... -p 2801:2801 -p 127.0.0.1:2802:2802 ...
curl -s localhost:2802/api/v1/pipeline/status
```

At startup each output probes its destination. A configuration error (rejected credentials, wrong path, untrusted certificate) in an output file stops the process with the reason in the log; in an output created through the API it leaves that output `failed` and the others start. An unreachable destination does not: the output starts as `degraded` (see [configuration](configuration.md#output-status)).

## Kubernetes

Mount both files from a ConfigMap. Output files are watched: editing the ConfigMap reloads outputs without a restart, once the kubelet has propagated it (about a minute). Put secrets in a Secret and point to them with the `_file` fields, for example `password_file`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falcosidekick
data:
  sidekick.yaml: |
    listen_port: 2801
    log_format: json
  outputs.yaml: |
    outputs:
      webhook:
        host: "http://receiver.default.svc:8080"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falcosidekick
spec:
  replicas: 1
  selector:
    matchLabels: {app: falcosidekick}
  template:
    metadata:
      labels: {app: falcosidekick}
    spec:
      containers:
        - name: falcosidekick
          image: falcosecurity/falcosidekick:v3-latest
          args: ["-c", "/etc/falcosidekick/sidekick.yaml", "-o", "/etc/falcosidekick/outputs.yaml"]
          ports:
            - containerPort: 2801
          readinessProbe:
            httpGet: {path: /healthz, port: 2801}
          volumeMounts:
            - name: config
              mountPath: /etc/falcosidekick
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: falcosidekick
---
apiVersion: v1
kind: Service
metadata:
  name: falcosidekick
spec:
  selector: {app: falcosidekick}
  ports:
    - port: 2801
      targetPort: 2801
```

## Point Falco to Falcosidekick

In `falco.yaml`:

```yaml
json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: "http://falcosidekick:2801/"
```

## Web UI

The UI is off by default, also in the UI image. To enable it, add an `inmemory` output, which stores recent events for the UI, and in `sidekick.yaml`:

```yaml
ui:
  enabled: true
  event_source: inmemory
```

The UI is served on the management port, 2802, with the API. In Kubernetes reach it with `kubectl port-forward deploy/falcosidekick 2802`, which works with the default `127.0.0.1`. To expose it through a Service instead, set `management.listen_address: "0.0.0.0"` and restrict that Service to trusted clients: the API has no authentication. The UI only reads: outputs are created and changed through the API, which needs `api.allow_writes: true`.

## Keep API outputs across restarts

Outputs created through the API live in memory by default. To keep them, and the UI layout, use a database in `sidekick.yaml`; secrets must then be file paths, as in the output files.

One instance, with a volume:

```yaml
database:
  backend: sqlite
  sqlite:
    path: /var/lib/falcosidekick/sidekick.db
```

Several instances sharing outputs (each needs the same output files):

```yaml
database:
  backend: postgres
  postgres:
    host: postgres.default.svc
    database: falcosidekick
    user: falcosidekick
    password_file: /run/secrets/postgres-password
    sslmode: verify-full
```

See [configuration](configuration.md#database) for every setting.

## Build from source

Requires Go and [Bun](https://bun.sh).

```sh
make falcosidekick       # binary with the UI
make falcosidekick-slim  # binary without the UI
make image               # local image falcosidekick:local
```

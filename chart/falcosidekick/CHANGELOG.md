# Change Log

This file documents all notable changes to the `falcosidekick` Helm Chart for Falcosidekick v3. The
release numbering uses [semantic versioning](http://semver.org). The chart for Falcosidekick v2 is the `0.x` line.

## v1.0.0-beta.1

* Initial chart for Falcosidekick v3 (`3.0.0-beta.1`). It is not compatible with the values of the `0.x` chart.
* `config` and `outputs` are written as `sidekick.yaml` and `outputs.yaml` with the v3 keys. A change to `config` restarts the pods; a change to `outputs` reloads the outputs without a restart.
* `secrets` mounts existing Secrets under `/etc/falcosidekick/secrets/<name>` and adds them to `api.secret_dirs`.
* The web UI is on and read-only by default; `image.variant: slim` with the UI is refused.
* `database.backend`: `inmemory`, `sqlite` with a PersistentVolumeClaim and one replica, or `postgres` with a password Secret.
* Optional management Service, ServiceMonitor, Policy Report RBAC and PodDisruptionBudget.
* Rendering fails on credentials written in the values, on incoherent TLS or postgres settings, on `config` keys that contradict the values, and on `extraEnv` variables of the settings the chart reads.
* `extraOutputConfigMaps` adds output files from existing ConfigMaps; a `helm test` pod calls `/readyz`; a `startupProbe` covers `database.connect_timeout`.
* The sqlite claim is kept on uninstall; the PodDisruptionBudget defaults to `maxUnavailable: 1`; the pod requests 50m CPU and 64Mi of memory, without limits.
* Runs as UID and GID 65532 with a read-only root filesystem, no capabilities and the `RuntimeDefault` seccomp profile.

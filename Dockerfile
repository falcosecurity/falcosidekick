# syntax=docker/dockerfile:1.7

# The binary is static (CGO_ENABLED=0, pure-Go sqlite): it needs CA certificates and nothing else.
# distroless static ships them, tzdata and /etc/passwd, and runs as nonroot (UID and GID 65532).
ARG BASE_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

FROM ${BASE_IMAGE}

ARG TARGETPLATFORM
ARG BINARY=falcosidekick

COPY LICENSE /usr/share/doc/falcosidekick/LICENSE
COPY $TARGETPLATFORM/${BINARY} /usr/bin/falcosidekick

USER 65532:65532

# Falco events, /livez, /readyz and /metrics; the API and the UI listen on 2802, loopback by default.
EXPOSE 2801

ENTRYPOINT ["/usr/bin/falcosidekick"]

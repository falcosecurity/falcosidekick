# syntax=docker/dockerfile:1.7

# The binary is static (CGO_ENABLED=0, pure-Go sqlite): it needs CA certificates and nothing else.
# distroless static ships them, tzdata and /etc/passwd, and runs as nonroot (UID and GID 65532).
# The base image is a literal FROM, not an ARG: Dependabot updates only the images FROM names.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

ARG TARGETPLATFORM
ARG BINARY=falcosidekick

COPY LICENSE /usr/share/doc/falcosidekick/LICENSE
COPY $TARGETPLATFORM/${BINARY} /usr/bin/falcosidekick

USER 65532:65532

# Falco events, /livez, /readyz and /metrics; the API and the UI listen on 2802, loopback by default.
EXPOSE 2801

ENTRYPOINT ["/usr/bin/falcosidekick"]

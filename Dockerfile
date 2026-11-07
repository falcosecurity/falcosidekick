# syntax=docker/dockerfile:1.7

# Pinned by digest so a rebuild of the same commit uses the same base; Dependabot proposes updates.
ARG BASE_IMAGE=alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034

FROM ${BASE_IMAGE}

ARG TARGETPLATFORM
ARG BINARY=falcosidekick
ARG VARIANT=ui

LABEL MAINTAINER="Falco Maintainers"
LABEL org.opencontainers.image.source="https://github.com/falcosecurity/falcosidekick"
LABEL io.falcosecurity.falcosidekick.variant="${VARIANT}"

RUN apk add --update --no-cache ca-certificates gcompat \
    && addgroup -S falcosidekick \
    && adduser -u 1234 -S falcosidekick -G falcosidekick

USER 1234
WORKDIR /home/falcosidekick/app

COPY LICENSE .
COPY $TARGETPLATFORM/${BINARY} ./falcosidekick

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]

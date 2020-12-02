ARG BUILDER_IMAGE=golang:1.15.5-alpine
ARG BASE_IMAGE=alpine:3.12

FROM ${BUILDER_IMAGE} AS build-stage

RUN apk add --update --no-cache alpine-sdk ca-certificates librdkafka coreutils

WORKDIR /src
ADD . .

RUN go mod download
RUN go build -tags musl -gcflags all=-trimpath=/src -asmflags all=-trimpath=/src -a -installsuffix cgo -o falcosidekick .

# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER "Thomas Labarussias <issif+falcosidekick@gadz.org>"

RUN apk add --update --no-cache ca-certificates librdkafka

# Create user falcosidekick
RUN addgroup -S falcosidekick && adduser -u 1234 -S falcosidekick -G falcosidekick
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app
COPY --from=build-stage /src/LICENSE .
COPY --from=build-stage /src/falcosidekick .

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]

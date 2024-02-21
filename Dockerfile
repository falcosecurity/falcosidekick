ARG BASE_IMAGE=alpine:3.19
# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER "Thomas Labarussias <issif+falcosidekick@gadz.org>"

RUN apk add --update --no-cache ca-certificates gcompat

# Create user falcosidekick
RUN addgroup -S falcosidekick && adduser -u 1234 -S falcosidekick -G falcosidekick
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app
COPY LICENSE .
COPY falcosidekick .

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]
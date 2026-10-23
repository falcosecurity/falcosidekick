ARG BASE_IMAGE=alpine:3.22
# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER="Falco Maintainers"
ARG TARGETPLATFORM

# Require the trust store update for the eMudhra intermediate CA compromise.
RUN apk add --update --no-cache 'ca-certificates>=20261020-r0' gcompat

# Create user falcosidekick
RUN addgroup -S falcosidekick && adduser -u 1234 -S falcosidekick -G falcosidekick
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app
COPY LICENSE .
COPY $TARGETPLATFORM/falcosidekick .

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]

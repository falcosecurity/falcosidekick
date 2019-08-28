# Build image (Golang)
FROM golang:1.12-alpine3.10 AS build-stage
ENV GO111MODULE on
ENV CGO_ENABLED 0

RUN apk add --no-cache gcc git make

WORKDIR /src
ADD . .

RUN go mod download
RUN go build -o falcosidekick

# Final Docker image
FROM alpine:3.10 AS final-stage
LABEL MAINTAINER "Thomas Labarussias <issif+falcosidekick@gadz.org>"

RUN apk add --no-cache ca-certificates

# Create user falcosidekick
RUN addgroup -S falcosidekick && adduser -S falcosidekick -G falcosidekick
USER falcosidekick

WORKDIR ${HOME}/app
COPY --from=build-stage /src/falcosidekick .

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]

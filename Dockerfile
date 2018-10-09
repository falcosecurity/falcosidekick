FROM golang:alpine3.8 AS build-stage
RUN mkdir /src
WORKDIR /src
ADD . .
RUN go build -o falcosidekick

FROM alpine:3.8 AS final-stage
RUN apk add --no-cache ca-certificates
RUN mkdir /app
WORKDIR /app
COPY --from=build-env /src/falcosidekick .
ENTRYPOINT ["./falcosidekick"]

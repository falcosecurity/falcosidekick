# build stage
FROM golang:alpine AS build-env
RUN mkdir /src
WORKDIR /src
ADD . .
RUN go build -o falcosidekick

# final stage
FROM alpine
RUN mkdir /app
WORKDIR /app
COPY --from=build-env /src/falcosidekick .
ENTRYPOINT ["./falcosidekick"]
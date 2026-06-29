# Skybridge native wire-proxy (Go). Pure stdlib → tiny static binary.
# Which command to build: skybridge-agent (default), skybridge-gateway, or skybridge-edge.
ARG SKYBRIDGE_CMD=skybridge-agent
FROM golang:1.26 AS build
ARG SKYBRIDGE_CMD
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/skybridge ./cmd/${SKYBRIDGE_CMD}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/skybridge /usr/local/bin/skybridge
# Native client listeners (PG / MySQL / Mongo) and the gateway agent endpoint (:8010).
EXPOSE 15432 13306 27018 8010
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/skybridge"]

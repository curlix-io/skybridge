# Runs the Mongo TypeKind end-to-end demo runner against a real skybridge-agent + real MongoDB.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal ./internal
COPY cmd ./cmd
COPY examples/mongo-typekind-demo/runner ./examples/mongo-typekind-demo/runner
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/runner ./examples/mongo-typekind-demo/runner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/runner /usr/local/bin/runner
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/runner"]

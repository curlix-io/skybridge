# Runs the aiclassifier demo runner against the stub LLM server (see docker-compose.yml).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal ./internal
COPY examples/aiclassifier-demo/runner ./examples/aiclassifier-demo/runner
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/runner ./examples/aiclassifier-demo/runner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/runner /usr/local/bin/runner
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/runner"]

# Skybridge — Go data plane for governed native database access + edge tool execution.
# The wire-proxy core is stdlib-only; the edge binary adds gRPC + aws-sdk-go-v2 (committed stubs in
# internal/genpb, so `go build` still works offline once deps are cached).
GO       ?= go
GOFLAGS  ?=
BINDIR   ?= bin
LDFLAGS  ?= -s -w
BUF      ?= buf

.PHONY: all build agent gateway edge gen test race vet fmt lint tidy clean

all: build

build: agent gateway edge

agent:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-agent ./cmd/skybridge-agent

gateway:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-gateway ./cmd/skybridge-gateway

edge:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-edge ./cmd/skybridge-edge

# Regenerate the Go gRPC stubs for the call-home contracts (needs buf + protoc-gen-go[-grpc] on PATH).
gen:
	$(BUF) generate ../proto --template buf.gen.yaml \
	  --path ../proto/curlix/agent/v1/agent_runner.proto \
	  --path ../proto/curlix/connector/v1/connector_gateway.proto

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# gofmt check used in CI (fails if anything is unformatted).
lint:
	@out="$$(gofmt -l . )"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BINDIR) dist

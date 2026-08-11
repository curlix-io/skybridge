# Skybridge — Go data plane for governed native database access + edge tool execution.
# The wire-proxy core is stdlib-only; the edge role adds gRPC + aws-sdk-go-v2 (committed stubs in
# internal/genpb, so `go build` still works offline once deps are cached).
#
# One binary (./cmd/skybridge), one image — the role (agent/gateway/edge/labeller) is picked by the
# first argument at run time, e.g. `bin/skybridge agent` or `docker run <image> edge`, not by which
# binary was built. Query Studio dispatch (internal/edge/studiotransport, dbexec, dbquery) is always
# compiled in and simply stays dormant unless SKYBRIDGE_STUDIO_GATEWAY is set at runtime.
GO       ?= go
GOFLAGS  ?=
BINDIR   ?= bin
LDFLAGS  ?= -s -w
BUF      ?= buf
GOTAGS   ?=

.PHONY: all build gen test race vet fmt lint tidy clean verify

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "$(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge ./cmd/skybridge

# Regenerate the Go gRPC stubs for the call-home contracts (needs buf + protoc-gen-go[-grpc] on PATH).
gen:
	$(BUF) generate ../../proto --template buf.gen.yaml \
	  --path ../../proto/curlix/agent/v1/agent_runner.proto \
	  --path ../../proto/curlix/connector/v1/connector_gateway.proto \
	  --path ../../proto/curlix/studiogateway/v1/studio_gateway.proto

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

# Mirrors CI: lint, vet, then the race-enabled test suite.
verify: lint vet race

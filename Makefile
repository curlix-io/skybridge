# Skybridge — Go data plane for governed native database access + edge tool execution.
# The wire-proxy core is stdlib-only; the edge binary adds gRPC + aws-sdk-go-v2 (committed stubs in
# internal/genpb, so `go build` still works offline once deps are cached).
#
# The `querystudio` build tag adds Query Studio dispatch (internal/edge/studiotransport, dbexec,
# dbquery) to the edge binary — an optional extra excluded from the default build so this module
# has no required dependency on it. Use `make edge-querystudio`/`test-querystudio`/etc. to build/test
# with it.
GO       ?= go
GOFLAGS  ?=
BINDIR   ?= bin
LDFLAGS  ?= -s -w
BUF      ?= buf
GOTAGS   ?=

.PHONY: all build agent gateway edge edge-querystudio labeller gen test test-querystudio race race-querystudio vet vet-querystudio fmt lint tidy clean verify verify-querystudio

all: build

build: agent gateway edge

agent:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "$(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-agent ./cmd/skybridge-agent

gateway:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "$(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-gateway ./cmd/skybridge-gateway

edge:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "$(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-edge ./cmd/skybridge-edge

# skybridge-labeller: the periodic AI-based path-label scan job (docs/AI_PATH_LABELLING_DESIGN.md).
# Not part of the default `build` target — it's a separate, opt-in job most deployments don't run,
# same reasoning as edge-querystudio being its own target rather than folded into `edge`.
labeller:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "$(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-labeller ./cmd/skybridge-labeller

# Same as `edge`, but with Query Studio dispatch compiled in.
edge-querystudio:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -tags "querystudio $(GOTAGS)" -ldflags="$(LDFLAGS)" -o $(BINDIR)/skybridge-edge ./cmd/skybridge-edge

# Regenerate the Go gRPC stubs for the call-home contracts (needs buf + protoc-gen-go[-grpc] on PATH).
# internal/genpb/curlix/studiogateway/v1/*.pb.go carry a //go:build querystudio line — re-add it by
# hand after regenerating, since buf/protoc-gen-go doesn't preserve manually-added build constraints.
gen:
	$(BUF) generate ../../proto --template buf.gen.yaml \
	  --path ../../proto/curlix/agent/v1/agent_runner.proto \
	  --path ../../proto/curlix/connector/v1/connector_gateway.proto \
	  --path ../../proto/curlix/studiogateway/v1/studio_gateway.proto

test:
	$(GO) test ./...

test-querystudio:
	$(GO) test -tags querystudio ./...

race:
	$(GO) test -race ./...

race-querystudio:
	$(GO) test -race -tags querystudio ./...

vet:
	$(GO) vet ./...

vet-querystudio:
	$(GO) vet -tags querystudio ./...

fmt:
	$(GO) fmt ./...

# gofmt check used in CI (fails if anything is unformatted).
lint:
	@out="$$(gofmt -l . )"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BINDIR) dist

# Mirrors the default CI leg: lint, vet, then the race-enabled test suite.
verify: lint vet race

# Mirrors the querystudio CI leg: lint, vet, then the race-enabled test suite, with the tag on.
verify-querystudio: lint vet-querystudio race-querystudio

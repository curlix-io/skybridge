# Skybridge data plane (Go) — single binary, single image. The role (agent/gateway/edge/labeller)
# is picked by the container's runtime command/args, e.g. `docker run <image> edge`, not by a build
# arg — there is nothing left to select at build time.
#
# Base is python:3.13-slim + awscli rather than a distroless image: only the edge role's
# aws_readonly_cli tool (internal/edge/awsexec/cli.go) shells out to a real `aws` binary, but since
# this one image also runs agent/gateway/labeller, every deployment carries that layer even when it
# never uses it — an accepted trade-off of collapsing to a single image.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/skybridge ./cmd/skybridge

FROM python:3.13-slim
RUN pip install --no-cache-dir awscli && rm -rf /root/.cache /tmp/*
# kubectl: only the edge role's kubectl_exec/k8s_token_request tools (internal/edge/k8sexec,
# internal/edge/k8stoken) shell out to a real `kubectl` binary, but per this file's own top
# comment about awscli, every deployment carries this layer even when it never uses it — same
# accepted trade-off of collapsing agent/gateway/edge/labeller into one image. python:3.13-slim
# has no curl by default, so install it first (removed again in the same layer).
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    ARCH=$(dpkg --print-architecture) && \
    curl -fsSL -o /usr/local/bin/kubectl \
    "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl" && \
    chmod +x /usr/local/bin/kubectl && \
    apt-get purge -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /out/skybridge /usr/local/bin/skybridge
EXPOSE 15432 13306 27018 8010
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/skybridge"]

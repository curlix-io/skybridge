# Exposing the tunnel stack for an external tester (ngrok)

This walks through standing up Skybridge's TUNNEL deployment shape locally
(`docker-compose.tunnel.yml` — `skybridge-agent` and `skybridge-edge` each dialing out to
`skybridge-gateway`, which relays already-masked native-client wire connections) and exposing it
through ngrok so someone outside this machine (e.g. a Curlix teammate) can connect and test it,
without opening any router/firewall ports.

Everything here runs against real containers (a real Postgres, real masking chain) except the
optional `labeller` service's LLM classification, which has no working default in this sandbox —
see [Testing the labeller](#testing-the-labeller-dynamic-discovery) below for what that does and
doesn't prove without a real LLM endpoint.

## 1. Prerequisites

- Docker + Docker Compose (already required to build/run this repo — see the main
  [README](../README.md#quick-start)).
- ngrok, installed once:

  ```sh
  brew install ngrok
  ```

  Then sign up at https://ngrok.com (free tier is enough) and authenticate:

  ```sh
  ngrok config add-authtoken <your-authtoken-from-the-ngrok-dashboard>
  ```

## 2. Bring up the tunnel stack

```sh
cd deploy
docker compose -f docker-compose.tunnel.yml up --build -d
```

This starts: a seeded Postgres, a stub control-plane (just enough for the gateway to resolve a
relay target — see `tunnel/stub_control_plane.py`'s doc comment for exactly what it implements and
why), Presidio (analyzer + anonymizer), `skybridge-gateway`, and both `skybridge-agent` and
`skybridge-edge` dialing into it under two different orgs.

Confirm it's healthy:

```sh
docker compose -f docker-compose.tunnel.yml ps
docker compose -f docker-compose.tunnel.yml logs -f gateway
```

Sanity-check locally first, before exposing anything:

```sh
psql "postgres://user:pass@localhost:25433/appdb"   # relayed via skybridge-agent (org: org-agent)
psql "postgres://user:pass@localhost:25434/appdb"   # relayed via skybridge-edge  (org: org-edge)
```

Both are the same underlying Postgres, relayed through two different paths — either one is enough
to demonstrate the masking chain end to end.

## 3. Expose it with ngrok

Postgres speaks a raw TCP wire protocol, not HTTP, so use ngrok's `tcp` mode — one tunnel per port
you want reachable. In two separate terminals (or `ngrok start` with a config file, see below):

```sh
ngrok tcp 25433   # org-agent path
ngrok tcp 25434   # org-edge path
```

Each prints a public address like `tcp://0.tcp.ngrok.io:41231`. Give that to whoever's testing —
they connect the same way, just swapping the host:port:

```sh
psql "postgres://user:pass@0.tcp.ngrok.io:41231/appdb"
```

To run both from one `ngrok start -all` with a single config file instead of two terminals:

```yaml
# ~/.config/ngrok/ngrok.yml (or wherever `ngrok config check` says it looks)
tunnels:
  skybridge-agent:
    proto: tcp
    addr: 25433
  skybridge-edge:
    proto: tcp
    addr: 25434
```

```sh
ngrok start --all
```

**This exposes an unauthenticated Postgres wire protocol to the public internet for as long as
the tunnel runs** (the tunnel test's `user`/`pass` are throwaway credentials against a throwaway
seeded database — nothing behind the masking chain is real data — but the *tunnel* itself has no
extra auth beyond that password). Only run this for the duration of the test, and tear it down
(`Ctrl-C` the ngrok process) as soon as you're done.

## 4. Testing the labeller (dynamic discovery)

Bring up the labeller as an add-on profile, pointed at the same stack's real Postgres:

```sh
docker compose -f docker-compose.tunnel.yml --profile labeller up --build -d labeller
docker compose -f docker-compose.tunnel.yml logs -f labeller
```

You should see log lines like:

```
skybridge-labeller: starting, db_type=postgres database=appdb tables=[] ...
skybridge-labeller: scanned N/N tables (M fields), proposed 0 labels ...
```

`tables=[]` confirms it's using dynamic discovery (`SKYBRIDGE_LABELLER_TABLES` is unset), not an
explicit list — it crawled `information_schema.tables` itself. `proposed 0 labels` is expected:
this compose file has no real LLM endpoint configured
(`SKYBRIDGE_LABELLER_LLM_ENDPOINT` defaults to a placeholder that fails every `Classify` call,
best-effort/non-fatal per `aiclassifier.Classifier`'s contract — see the service's comment in
`docker-compose.tunnel.yml`). This proves the **discovery and scan-scheduling** work
(`MaxObjectsPerScan`/`RescanIntervalSeconds` — see `docs/AI_PATH_LABELLING_DESIGN.md` §8 item 9),
not real PII classification.

To test real classification too, override the LLM env vars with a real endpoint before bringing the
service up:

```sh
export SKYBRIDGE_LABELLER_LLM_ENDPOINT="https://your-llm-endpoint/v1/chat/completions"
export SKYBRIDGE_LABELLER_LLM_API_KEY="sk-..."
docker compose -f docker-compose.tunnel.yml --profile labeller up --build -d labeller
```

The labeller only ever *proposes* labels (`label.Source == proposed`) — it never redacts anything
on its own, and this smoke test's `SKYBRIDGE_PATH_LABEL_URL` points at the stub control-plane, which
doesn't implement the real pii-path-labels routes, so proposals will fail to push (logged, not
fatal). Point it at a real control-plane URL to see proposals actually land somewhere reviewable.

## 5. Tear down

```sh
docker compose -f docker-compose.tunnel.yml --profile labeller down -v
```

`-v` also removes the seeded Postgres volume, so the next `up` starts from a clean seed.

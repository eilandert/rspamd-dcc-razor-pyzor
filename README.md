# rspamd-dcc-razor-pyzor

A small, standalone Docker backend that brings the three classic
collaborative-filtering networks — **DCC**, **Razor** and **Pyzor** — to
[rspamd](https://rspamd.com) through a single HTTP endpoint, plus the rspamd
plugin that talks to it.

The image runs **no rspamd of its own**. Your rspamd stays in its own container
(or on the host); you drop the plugin shipped here into it and point the plugin
at this backend.

**Why a separate backend?** rspamd has a built-in DCC module but nothing for
Razor or Pyzor, and shelling out to those CLIs from inside the rspamd worker
would block its event loop. This service is a single static Go binary that
speaks **all three networks in-process** — Razor, Pyzor and DCC via the
[gazor](https://github.com/eilandert/gazor),
[gyzor](https://github.com/eilandert/gyzor) and
[gdcc](https://github.com/eilandert/gdcc) libraries — answering over HTTP, so
the plugin stays fully asynchronous and a single request covers all three
networks at once, with **no per-message subprocess forks at all**.

## How it works

```
  ┌──────────────────────┐   HTTP :8077 + token   ┌────────────────────────────┐
  │  rspamd (your image)  │ ─────────────────────► │  rspamd-dcc-razor-pyzor     │
  │  dcc_razor_pyzor.lua  │  POST /check (message) │  gozer  (distroless, nonroot)│
  └──────────────────────┘ ◄───────────────────── │   ├─ gdcc   (DCC,   in-proc) │
                              JSON verdict         │   ├─ gazor  (Razor, in-proc) │
                                                   │   └─ gyzor  (Pyzor, in-proc) │
                                                   └────────────────────────────┘
```

The image is a single ~19 MB static `gozer` binary on a `distroless/static`
base — no Debian, no s6 supervisor, no shell, no per-message fork. `gozer` is
the container entrypoint and runs as `nonroot`. It queries the three networks
**concurrently**, all in-process, and caches verdicts (see
[Configuration](#configuration)). All three talk to their servers directly
(DCC needs no `dccifd` daemon). Every backend is **best-effort**: if one network
is unreachable it simply doesn't score, and the container stays healthy — the
healthcheck only depends on gozer's `/health` (probed by `gozer health`, since
the image ships no shell or curl).

**Hardening:** gozer runs non-root with bounded concurrency, every POST is
**token-authenticated**, and the bundled compose runs the container read-only
with `cap_drop: ALL`, `no-new-privileges`, and no published host port.

### Privacy: the message never touches disk

Gozer keeps the message in memory: all three checksums (Razor, Pyzor and DCC)
are computed in-process — nothing is ever written to a temp file.
The cache stores only `sha256(body) → verdict` (never the body itself), and the
same goes for the optional Redis backend, so no message content is ever persisted
locally.

(This is also why a `tmpfs` overlay would do nothing for speed: there is no
per-message disk write to accelerate. The latency is **network** round-trips to
the DCC/Razor/Pyzor servers.)

The only thing that leaves the container is what collaborative filtering needs:
**content fingerprints** — DCC checksums, Razor signatures, Pyzor digests — sent
to those networks (and, on `/report`, a spam submission). The raw message is
never uploaded.

## Quick start

### 1. Run the backend

Gozer rejects every POST until a token is configured, and it isn't published
to the host — so run it with compose:

```bash
cd docker
mkdir -p secrets && openssl rand -hex 32 > secrets/drp_token.txt
docker compose up -d        # docker/docker-compose.yml
```

Containers on the same Docker network now reach it at `http://rspamd-drp:8077`.
Give your rspamd (and Dovecot) the same token.

### 2. Install the plugin into rspamd

The plugin lives in [`rspamd/`](rspamd/) at the repo root (it is **not** baked
into the backend image):

```bash
cp rspamd/plugins/dcc_razor_pyzor.lua  /etc/rspamd/plugins/
cp rspamd/local.d/dcc_razor_pyzor.conf /etc/rspamd/local.d/
cp rspamd/local.d/groups.conf          /etc/rspamd/local.d/   # symbol scores
echo 'dofile("/etc/rspamd/plugins/dcc_razor_pyzor.lua")' >> /etc/rspamd/rspamd.local.lua
```

Then set the backend URL and the **same token** in `local.d/dcc_razor_pyzor.conf`:

```
url   = "http://rspamd-drp:8077/check";   # backend host:port
token = "the-shared-secret";              # must equal gozer's GOZER_TOKEN
```

> **Heads-up on DNS:** rspamd resolves URLs through its own configured resolver.
> If that resolver can't see Docker service names (for example an RBL-only
> unbound), use the backend's **IP address** in `url` instead of `rspamd-drp`.

Restart rspamd. The plugin adds three symbols, scored in `groups.conf` (tune to
taste):

| Symbol | Meaning |
|--------|---------|
| `DRP_DCC_BULK` | DCC reports the body as bulk |
| `DRP_RAZOR` | Razor signature match |
| `DRP_PYZOR` | Pyzor sightings above threshold |

## Identities

Each network has an identity, auto-created on first boot and kept in the named
volumes (`drp-razor`, `drp-dcc`, `drp-pyzor`):

| Network | Identity | Anonymous default |
|---------|----------|-------------------|
| Razor | account supplied via `RAZOR_USER`/`RAZOR_PASS` | yes (anonymous) |
| DCC | `DCC_CLIENT_ID` + `DCC_CLIENT_PASSWD` (or `DCC_IDS`) | yes (anonymous id 1) |
| Pyzor | optional accounts file under `PYZOR_HOME` | yes (anonymous to the public server) |

Anonymous is fine for most setups. The image carries **no writable state**;
to use a **known or shared identity**, provide it through the environment (every
var also accepts a `<VAR>_FILE` form for Docker secrets — see
[`docker/docker-compose.yml`](docker/docker-compose.yml)):

```yaml
environment:
  DCC_CLIENT_ID: "1234567"
  DCC_CLIENT_PASSWD: "…"          # or DCC_IDS: <path to a DCC ids file>
  RAZOR_USER: "you@example.com"   # obtain one with `gozer razor-register`
  RAZOR_PASS: "…"
```

### DNS-bypass server overrides

When the container's DNS is flaky or the public discovery servers are
unreachable, each network's server list can be pinned explicitly, bypassing DNS
discovery entirely. Gozer forwards these to the matching in-process client
(`gdcc`, `gyzor`, `gazor`); each accepts a comma list of `host[:port]`
(hostname, IPv4, or bracketed IPv6 `[::1]:port`):

```yaml
environment:
  DCC_SERVERS:     "dcc1.dcc-servers.net,dcc2.dcc-servers.net"  # → gdcc
  GYZOR_SERVERS:   "public.pyzor.org:24441"                     # → gyzor (Pyzor)
  GAZOR_DISCOVERY: "discovery.razor.cloudmark.com"              # → gazor (Razor), tried in order
```

Resolution order per network: **explicit env → existing credential in the volume
→ anonymous**. For Razor that means `RAZOR_USER`+`RAZOR_PASS` win, else the
persisted `gazor-identity` file, else a fresh registration. Every credential
variable also accepts a `<VAR>_FILE` form for
Docker secrets — e.g. `RAZOR_REGISTER_PASS_FILE=/run/secrets/razor_pass` — so a
secret never has to sit in the compose file.

## Configuration

Every setting is a backend-container **environment variable** and also a
**`gozer serve` CLI flag** (flag > env > default), so the same option works in
compose or on the command line. The flag name is the env name lower-cased,
de-prefixed and hyphenated — e.g. `GOZER_MAX_CONCURRENT` ↔ `--max-concurrent`,
`GYZOR_SERVERS` ↔ `--pyzor-servers`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `GOZER_TOKEN` / `GOZER_TOKEN_FILE` | — | Shared secret for POST auth. **Required** — without it every POST returns 503. |
| `GOZER_HOST` / `GOZER_PORT` | `0.0.0.0` / `8077` | Bind address. |
| `GOZER_CACHE_TTL` | `300` | Verdict cache lifetime in seconds (`0` disables). Bulk mail repeats, so cache hits are the main speed-up. |
| `GOZER_CACHE_SIZE` | `4096` | In-memory cache entries (LRU). |
| `GOZER_REDIS_URL` | — | Use Redis for the cache so **multiple scanners share** it, e.g. `redis://valkey:6379/5`. Otherwise the cache is in-process. |
| `GOZER_REDIS_PREFIX` | `drp:check:` | Key prefix in Redis. |
| `GOZER_MAX_CONCURRENT` | `8` | Max in-flight requests (bounds backend fan-out). |
| `GOZER_BACKEND_TIMEOUT` | `6` | Per-backend timeout in seconds. |
| `GOZER_VERBOSE` | `0` (off) | Per-request logging — access line plus verdict, timing and cache hit/miss; also dumps the resolved config at startup. Off by default (only startup and errors are logged). |
| `GOZER_LOG_STDOUT` | `0` (off) | Send **info/access** logs to stdout instead of stderr. **Errors and warnings always stay on stderr** so a log shipper can separate and alert on them. Both streams are captured by Docker regardless. |
| `RAZOR_MIN_CF` | `ac` | Razor minimum confidence: `ac`, `ac+N`, `ac-N`, or a number. |
| `DCC_SERVERS` / `GYZOR_SERVERS` / `GAZOR_DISCOVERY` | — | DNS-bypass server overrides forwarded to gdcc / gyzor / gazor (see above). |
| `TZ` | — | Container timezone. |

## Benchmarks

From `go test -bench` (Go 1.26, 32-core host); reproduce with the commands shown.

**Request path / throughput** — `go test -bench BenchmarkServe ./internal/gozer`
drives the full server (auth, concurrency gate, cache, single-flight, dispatch)
against a 2&nbsp;ms synthetic backend, over a mixed cache-hit ratio:

| cache hit ratio | throughput | backend calls / request |
|-----------------|-----------:|------------------------:|
| 90 % | ~29,600 msg/s | 0.11 |
| 50 % | ~11,500 msg/s | 0.53 |
| 0 % (all miss) | ~11,800 msg/s | 1.01 |

The verdict cache is the lever: at a 90 % hit ratio only ~1 request in 9 reaches
a backend, and gozer clears 1000 msg/s comfortably even all-miss. The in-process
cache hit itself is **~55 ns, zero allocations**; an at-capacity LRU insert is
~344 ns.

**Fingerprint compute** (offline, one 256 KiB message) — the in-process CPU cost
per network, all dwarfed by network RTT:

| client | per message | allocations |
|--------|------------:|------------:|
| gdcc — DCC checksums | ~3.2 ms (81 MB/s) | 24 |
| gyzor — Pyzor digest | ~4.5 ms (58 MB/s) | 50 |
| gazor — Razor signatures | ~8.4 ms (31 MB/s) | 833 |

**Network round-trips dominate the cold path** (anonymous, public servers,
varies with distance): Pyzor ~50 ms, DCC ~170 ms, Razor ~1 s (multi-step
discovery handshake). gozer queries all three **concurrently, in-process**, so a
cold `/check` ≈ the slowest backend (Razor), not the sum — and a cached `/check`
is a sub-millisecond local lookup.

## HTTP API

The request body is always the raw RFC-822 message. POST endpoints require the
token, sent as `Authorization: Bearer <token>` or `X-DRP-Token: <token>`
(`401` if it's wrong, `503` if gozer has no token). `/health` needs no auth.

- **`POST /check`** — query only, never reports. Used by the rspamd plugin.

  ```json
  { "dcc":   { "action": "reject", "bulk": 2147483647 },
    "razor": { "hit": true },
    "pyzor": { "count": 42, "wl": 0 } }
  ```

- **`POST /report`** — report the message as **spam** to all three networks.

  ```json
  { "dcc": true, "razor": true, "pyzor": true }
  ```

- **`POST /revoke`** — report as **ham**. Razor and Pyzor support this; DCC has
  no network un-report, so its value is `null`.

- **`GET /health`** — `200 ok`, used by the container healthcheck.

- **`GET /metrics`** — Prometheus exposition (no auth): per-endpoint request
  counters (`gozer_check_total`, `gozer_report_total`, `gozer_revoke_total`),
  `gozer_error_total`, `gozer_busy_total`, cache hit/miss/coalesced, Redis
  health (`gozer_redis_error_total`, `gozer_redis_circuit_open_total`),
  per-backend errors (`gozer_backend_error_total{backend="dcc|razor|pyzor"}`)
  and a `gozer_latency_seconds` histogram. `gozer stats` fetches and prints it locally
  (the image ships no curl).

### Example

POST the raw message as the body — `--data-binary` keeps the bytes intact (the
fingerprints are computed over them). From a container on the same network (or
the host if you published the port):

```sh
TOKEN=$(cat docker/secrets/drp_token.txt)

# scan
curl -s --data-binary @message.eml \
  -H "Authorization: Bearer $TOKEN" http://rspamd-drp:8077/check
# {"dcc":{"action":"unknown","bulk":null},"razor":{"hit":false},"pyzor":{"count":42,"wl":0}}

# user feedback (X-DRP-Token works in place of the Bearer header)
curl -s --data-binary @spam.eml -H "X-DRP-Token: $TOKEN" http://rspamd-drp:8077/report
curl -s --data-binary @ham.eml  -H "X-DRP-Token: $TOKEN" http://rspamd-drp:8077/revoke
curl -s http://rspamd-drp:8077/metrics      # no auth
```

## Reporting from Dovecot (sieve)

`/check` is for scanning. `/report` and `/revoke` are for **user feedback** —
when someone moves a message into Junk (spam) or rescues it back out (ham).
Sieve can't speak HTTP, so [`dovecot/drp-report`](dovecot/drp-report) bridges the
message to gozer, triggered by imapsieve.

The [`eilandert/dovecot`](https://github.com/eilandert/dockerized) image already
bakes this in. To wire it into **any other** Dovecot host (needs `curl` and
`dovecot-sieve`):

```bash
cp dovecot/drp-report              /usr/lib/dovecot/sieve-pipe/drp-report   # chmod 0755
cp dovecot/sieve/report-spam.sieve /usr/lib/dovecot/sieve/
cp dovecot/sieve/report-ham.sieve  /usr/lib/dovecot/sieve/
sievec /usr/lib/dovecot/sieve/report-spam.sieve
sievec /usr/lib/dovecot/sieve/report-ham.sieve
cp dovecot/90-drp-sieve.conf       /etc/dovecot/conf.d/

# sieve_extprograms scrubs the environment, so pass the URL + token via a file:
printf 'DRP_URL=http://rspamd-drp:8077\nDRP_TOKEN=the-shared-secret\n' \
  > /etc/dovecot/drp.env

doveadm reload
```

What it does ([`90-drp-sieve.conf`](dovecot/90-drp-sieve.conf)):

| User action (IMAP) | Sieve script | Gozer call |
|--------------------|--------------|-----------|
| move/copy **into** `Junk` | `report-spam.sieve` | `POST /report` (spam) |
| move **out of** `Junk` | `report-ham.sieve` | `POST /revoke` (ham) |

`drp-report` always exits 0, so a reporting hiccup never bounces mail or blocks
the IMAP move.

## Build

```bash
docker build -f docker/Dockerfile-deb -t eilandert/rspamd-dcc-razor-pyzor:latest docker/
```

In the [dockerized](https://github.com/eilandert/dockerized) monorepo this repo
is a submodule at `src/rspamd-dcc-razor-pyzor`; build it with
`docker buildx bake debian-rspamd-drp`.

> **Packages:** none. The runtime is `distroless/static` plus the single static
> `gozer` binary — no Debian, no apt, no perl/python, no `dcc` package
> (dccproc/cdcc), no shell. All three clients are linked in.

## The Go rewrite: gazor, gyzor, gdcc, gozer

Earlier versions of this backend were a thin Python HTTP shim that, for every
message, forked the perl `razor-check` / `razor-report`, the python `pyzor` and
the `dccproc` CLIs. That meant an interpreter (and a set-UID `dccproc`) start
per check and a perl + python + dcc toolchain baked into the image. All three
clients were rewritten from scratch in Go and are now linked into the backend
in-process:

| Was (per-message fork) | Now (in-process Go) | What it is |
|------------------------|---------------------|------------|
| perl `razor-agents` (Razor2) | [gazor](https://github.com/eilandert/gazor) | Go razor client |
| python `pyzor` | [gyzor](https://github.com/eilandert/gyzor) | Go pyzor client |
| set-UID `dccproc` (dcc package) | [gdcc](https://github.com/eilandert/gdcc) | Go DCC client |
| python `spamcheck_shim.py` | **gozer** | this backend — the binary in the image |

gazor, gyzor and gdcc speak their wire protocols byte-for-byte compatibly with
the reference perl/python/C clients (each is gated by parity tests against real
razor, pyzor and `dccproc` in its own CI), so the servers see identical
fingerprints and the switch is invisible on the wire. With **no per-message fork
left**, the image dropped from ~268 MB (perl/python/dcc + s6 on Debian) to a
**~19 MB distroless static binary**.

Upgrading from an older build: the backend's environment variables were renamed
`SHIM_*` to `GOZER_*` (for example `SHIM_TOKEN` becomes `GOZER_TOKEN`). The HTTP
contract, the `X-DRP-*` headers, and `drp-report`'s `DRP_URL` / `DRP_TOKEN` are
unchanged.

## See also

- Docker Hub: <https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor>
- Monorepo: <https://github.com/eilandert/dockerized>
- Article: <https://deb.myguard.nl/2026/06/rspamd-dcc-razor-pyzor-docker-backend/>
- gazor (Razor client, imported in-process): <https://github.com/eilandert/gazor>
- gyzor (Pyzor client, imported in-process): <https://github.com/eilandert/gyzor>
- gdcc (DCC client, imported in-process): <https://github.com/eilandert/gdcc>

## License

MIT — see [LICENSE](LICENSE).

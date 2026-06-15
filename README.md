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
speaks **Razor and Pyzor in-process** (the [gazor](https://github.com/eilandert/gazor)
and [gyzor](https://github.com/eilandert/gyzor) libraries) and runs **DCC** via
`dccproc`, answering over HTTP — so the plugin stays fully asynchronous and a
single request covers all three networks at once, with no per-message perl/python
process forks.

## How it works

```
  ┌──────────────────────┐   HTTP :8077 + token   ┌────────────────────────────┐
  │  rspamd (your image)  │ ─────────────────────► │  rspamd-dcc-razor-pyzor     │
  │  dcc_razor_pyzor.lua  │  POST /check (message) │  gozer  (s6, drp)           │
  └──────────────────────┘ ◄───────────────────── │   ├─ dccproc (set-UID dcc)  │
                              JSON verdict         │   ├─ gazor  (Razor, in-proc)│
                                                   │   └─ gyzor  (Pyzor, in-proc)│
                                                   └────────────────────────────┘
```

Inside the image (supervised by s6-overlay):

- **`gozer`** — the static Go HTTP server on `:8077` running as the
  unprivileged `drp` user. It queries the three networks **concurrently**
  (Razor/Pyzor in-process, DCC via `dccproc`) and caches verdicts (see
  [Configuration](#configuration)).
- **`init-bootstrap`** — one-shot setup of the DCC map, Razor identity and Pyzor
  server list.

`dccproc` talks to the DCC servers directly (no `dccifd` daemon needed). Every
backend is **best-effort**: if one network is unreachable it simply doesn't
score, and the container stays healthy — the healthcheck only depends on the
gozer's `/health`.

**Hardening:** gozer runs non-root with bounded concurrency, every POST is
**token-authenticated**, and the bundled compose runs the container read-only
with `cap_drop: ALL`, `no-new-privileges`, and no published host port.

### Privacy: the message never touches disk

Gozer keeps the message in memory: Razor and Pyzor are computed in-process,
and DCC is fed to `dccproc` over **stdin** — nothing is written to a temp file.
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
| Razor | nomination credential auto-registered by `gozer` | yes (random identity) |
| DCC | client-id in `/var/dcc/ids` | yes (anonymous id) |
| Pyzor | optional accounts file | yes (anonymous to the public server) |

Anonymous is fine for most setups. To use a **known or shared identity** — one
that survives a volume reset or is reused across instances — provide it through
the environment (see [`docker/docker-compose.yml`](docker/docker-compose.yml)):

```yaml
environment:
  DCC_CLIENT_ID: "1234567"
  DCC_CLIENT_PASSWD: "…"          # or DCC_IDS: <whole /var/dcc/ids file>
  RAZOR_REGISTER_USER: "you@example.com"   # register/link this account
  RAZOR_REGISTER_PASS: "…"
  # or, for an account you already hold, skip registration and supply it directly:
  RAZOR_USER: "you@example.com"
  RAZOR_PASS: "…"
  PYZOR_SERVERS: "public.pyzor.org:24441"
```

Resolution order per network: **explicit env → existing credential in the volume
→ anonymous**. For Razor that means `RAZOR_USER`+`RAZOR_PASS` win, else the
persisted `gazor-identity` file, else a fresh registration. Every credential
variable also accepts a `<VAR>_FILE` form for
Docker secrets — e.g. `RAZOR_REGISTER_PASS_FILE=/run/secrets/razor_pass` — so a
secret never has to sit in the compose file.

## Configuration

All settings are environment variables on the backend container:

| Variable | Default | Purpose |
|----------|---------|---------|
| `GOZER_TOKEN` / `GOZER_TOKEN_FILE` | — | Shared secret for POST auth. **Required** — without it every POST returns 503. |
| `GOZER_CACHE_TTL` | `300` | Verdict cache lifetime in seconds (`0` disables). Bulk mail repeats, so cache hits are the main speed-up. |
| `GOZER_CACHE_SIZE` | `4096` | In-memory cache entries (LRU). |
| `GOZER_REDIS_URL` | — | Use Redis for the cache so **multiple scanners share** it, e.g. `redis://valkey:6379/5`. Otherwise the cache is in-process. |
| `GOZER_REDIS_PREFIX` | `drp:check:` | Key prefix in Redis. |
| `GOZER_MAX_CONCURRENT` | `8` | Max in-flight requests (bounds backend fan-out). |
| `GOZER_BACKEND_TIMEOUT` | `6` | Per-backend timeout in seconds. |
| `GOZER_VERBOSE` | `0` (off) | Per-request logging — access line plus verdict, timing and cache hit/miss. Off by default (only startup and errors are logged). |
| `RAZOR_MIN_CF` | `ac` | Razor minimum confidence: `ac`, `ac+N`, `ac-N`, or a number. |
| `TZ` | — | Container timezone. |

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

> **Packages:** `dcc`, `razor` and `pyzor` come from our own Debian packages on
> [deb.myguard.nl](https://deb.myguard.nl) (the apt repo and signing key are
> already in `eilandert/debian-base`). DCC isn't in Debian proper for licence
> reasons; the `dcc` package provides `dccifd`, `dccproc` and `cdcc`.

## See also

- Docker Hub: <https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor>
- Monorepo: <https://github.com/eilandert/dockerized>
- Article: <https://deb.myguard.nl/2026/06/rspamd-dcc-razor-pyzor-docker-backend/>
- gazor (Razor client, imported in-process): <https://github.com/eilandert/gazor>
- gyzor (Pyzor client, imported in-process): <https://github.com/eilandert/gyzor>

## License

MIT — see [LICENSE](LICENSE).

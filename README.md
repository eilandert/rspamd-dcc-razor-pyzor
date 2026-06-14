# rspamd-dcc-razor-pyzor

A **standalone Docker backend** that exposes the three classic
collaborative-filtering networks — **DCC**, **Razor** and **Pyzor** — over one
HTTP endpoint, plus the [rspamd](https://rspamd.com) plugin that queries it.

The image runs **no rspamd**. rspamd lives in its own container (or host); you
install the plugin shipped here into that rspamd and point it at this backend.

Why: rspamd ships a native DCC module but has no native Razor or Pyzor support,
and running those CLIs inside the rspamd worker would block its event loop. This
backend runs the CLIs out-of-process and answers over HTTP, so the plugin stays
fully async and one round-trip covers all three networks.

## Architecture

```
  ┌──────────────────────┐        HTTP :8077        ┌────────────────────────────┐
  │  rspamd (your image)  │ ───────────────────────► │  rspamd-dcc-razor-pyzor     │
  │  dcc_razor_pyzor.lua  │   POST /check (message)  │  spamcheck_shim (s6)        │
  └──────────────────────┘ ◄─────────────────────── │   ├─ dccproc → dccifd (s6)  │
                              JSON verdict           │   ├─ razor-check            │
                                                     │   └─ pyzor check            │
                                                     └────────────────────────────┘
```

This image (s6-overlay supervised):
- `shim` longrun — `spamcheck_shim.py`, HTTP on `:8077`, wraps the CLIs.
- `dccifd` longrun — DCC interface daemon the shim's `dccproc` uses.
- `init-bootstrap` oneshot — DCC map / Razor identity / Pyzor servers setup.

Each backend is **best-effort**: a dead network degrades scoring, never
availability. The container healthcheck only requires the shim's `/health`.

## 1. Run the backend

```bash
docker run -d --name rspamd-drp \
  -p 8077:8077 \
  -v drp-razor:/var/lib/razor -v drp-pyzor:/var/lib/pyzor -v drp-dcc:/var/dcc \
  eilandert/rspamd-dcc-razor-pyzor:latest
```

or `docker compose up -d` (see [docker-compose.yml](docker-compose.yml)).

Keep `:8077` on a private network — it accepts raw messages and has no auth.

## 2. Install the plugin into your rspamd

```bash
cp rspamd/plugins/dcc_razor_pyzor.lua /etc/rspamd/plugins/
cp rspamd/local.d/dcc_razor_pyzor.conf /etc/rspamd/local.d/
cp rspamd/local.d/groups.conf          /etc/rspamd/local.d/   # symbol scores
echo 'dofile("/etc/rspamd/plugins/dcc_razor_pyzor.lua")' >> /etc/rspamd/rspamd.local.lua
```

Point the plugin at the backend in `local.d/dcc_razor_pyzor.conf`:

```
url = "http://rspamd-drp:8077/check";   # backend container/host:port
```

Restart rspamd. Symbols (scores in `groups.conf`, tune to taste):

- `DRP_DCC_BULK` — DCC reports the body as bulk
- `DRP_RAZOR` — Razor signature match
- `DRP_PYZOR` — Pyzor sightings above threshold

## HTTP API

`POST /check` with the raw RFC-822 message as the body → JSON:

```json
{ "dcc":   { "action": "reject", "bulk": 2147483647 },
  "razor": { "hit": true },
  "pyzor": { "count": 42, "wl": 0 } }
```

`GET /health` → `200 ok` (used by the container HEALTHCHECK).

## Build

```bash
docker build -f Dockerfile-deb -t eilandert/rspamd-dcc-razor-pyzor:latest .
```

In the [dockerized](https://github.com/eilandert/dockerized) monorepo this
builds via the buildx-bake target `debian-rspamd-drp` (external context
`../rspamd-dcc-razor-pyzor`, same pattern as `../webtester`).

> **DCC note:** DCC has no Debian package (licence terms), so it is compiled
> from the upstream source tarball during the image build. If your build host
> has no outbound network to `dcc-servers.net`, DCC is skipped and the `dccifd`
> service idles — Razor and Pyzor still work.

## See also

- Docker Hub: https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor
- Monorepo: https://github.com/eilandert/dockerized
- Article: _(TODO: add deb.myguard.nl post link when published)_

## License

MIT — see [LICENSE](LICENSE).

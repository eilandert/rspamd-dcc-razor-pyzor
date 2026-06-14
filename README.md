# rspamd-dcc-razor-pyzor

An [rspamd](https://rspamd.com) plugin **and** a self-contained Debian Docker
image that scores mail against the three classic collaborative-filtering
networks — **DCC**, **Razor** and **Pyzor** — through one local HTTP shim.

rspamd ships a native DCC module but has no native Razor or Pyzor support, and
running those CLIs inside the worker would block its event loop. This project
solves both: a small async Lua plugin talks to an out-of-process HTTP shim that
runs the CLIs, so all three networks are covered in a single async round-trip.

## What's in the box

| Component | Role | Supervised by |
|-----------|------|---------------|
| `rspamd/plugins/dcc_razor_pyzor.lua` | async plugin; POSTs the message to the shim, maps each network to its own symbol | rspamd |
| `shim/spamcheck_shim.py` | stdlib HTTP wrapper around `dccproc` / `razor-check` / `pyzor` | s6 (`shim`) |
| `dccifd` | DCC interface daemon the shim queries | s6 (`dccifd`) |
| `rspamd` | the scanner | s6 (`rspamd`) |

Symbols (scores in `rspamd/local.d/groups.conf`, tune to taste):

- `DRP_DCC_BULK` — DCC reports the body as bulk
- `DRP_RAZOR` — Razor signature match
- `DRP_PYZOR` — Pyzor sightings above threshold

Each backend is **best-effort**: a dead network degrades scoring, never
availability. The container healthcheck only requires rspamd + the shim.

## Run

```bash
docker run -d --name rspamd-drp \
  -p 11332:11332 -p 11334:11334 \
  -v rspamd-data:/var/lib/rspamd \
  eilandert/rspamd-dcc-razor-pyzor:latest
```

or `docker compose up -d` (see [docker-compose.yml](docker-compose.yml)).

Wire it into your MTA the same way as any rspamd proxy/milter (port 11332);
the controller/web UI is on 11334.

## Use the plugin only (existing rspamd)

You don't need the image. Drop the plugin into an existing rspamd and point it
at a running shim:

```
cp rspamd/plugins/dcc_razor_pyzor.lua /etc/rspamd/plugins/
cp rspamd/local.d/dcc_razor_pyzor.conf /etc/rspamd/local.d/
cp rspamd/local.d/groups.conf          /etc/rspamd/local.d/
echo 'dofile("/etc/rspamd/plugins/dcc_razor_pyzor.lua")' >> /etc/rspamd/rspamd.local.lua
# run the shim somewhere reachable; set `url` in the .conf accordingly
python3 shim/spamcheck_shim.py
```

## Build

```bash
docker build -f Dockerfile-deb -t eilandert/rspamd-dcc-razor-pyzor:latest .
```

In the [dockerized](https://github.com/eilandert/dockerized) monorepo this
builds via buildx-bake targets `debian-rspamd-drp` / `ubuntu-rspamd-drp`.

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

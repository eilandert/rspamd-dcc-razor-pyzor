# razord — persistent Razor daemon

`razorfy.pl` is vendored from [HeinleinSupport/razorfy](https://github.com/HeinleinSupport/razorfy)
(Apache-2.0). It keeps a Razor2 agent warm and serves checks over TCP, avoiding
the perl-startup + agent-init cost of `razor-check` per message.

Protocol: connect, send the raw message, half-close the write side, read the
verdict string (`spam`|`ham`; fails safe to `ham`). The shim's `_razord_check`
speaks this; on any daemon error it falls back to the `razor-check` CLI.

Configured via env (see the s6 run script): `RAZORFY_BINDADDRESS=127.0.0.1`,
`RAZORFY_BINDPORT=11342`, `RAZORFY_RAZORHOME=/var/lib/razor`.

## NOT enabled by default

Benchmarked on the live stack: **razorfy ~1450 ms vs `razor-check` CLI ~330 ms**
per check — razorfy rebuilds its Razor2 agent per connection (`create_agent()` in
`clientHandler`), so it is ~4× slower than just forking the CLI. The shim
therefore defaults to the CLI (`SHIM_RAZORD_ADDR` empty) and this service is NOT
in the s6 `user` bundle. To opt in: add `razord` to `user/contents.d/` and set
`SHIM_RAZORD_ADDR=127.0.0.1:11342`. Kept for reference / future fix (persist the
agent across requests).

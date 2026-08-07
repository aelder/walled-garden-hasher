# Third-party sources

`make crosscheck` compiles the sources in this directory. The shipping miner —
everything under `src/`, `include/`, `net/`, `ui/`, and `ref/` — does not link
them.

The cross-check compares the native engine with a separately written deployed
implementation. It detected a case-4 Haraka round-constant difference that
passed 70,255 differential checks against the local reference. The required
upstream sources are pinned here to keep that comparison reproducible.

| Path | Origin | License |
|---|---|---|
| `verus/verus_clhash.{cpp,h}` | Verus Coin, © 2018 Michael Toutonghi | Apache-2.0 |
| `verus/haraka.{c,h}` | © 2016 kste | MIT |
| `verus/sse2neon/` | DLTcollab/sse2neon, submodule | MIT |

Unmodified. Their own notices are in the file headers and, for sse2neon, in its
`LICENSE`.

Both Apache-2.0 and MIT are compatible with GPL-3.0-or-later. Apache-2.0 is not
compatible with GPL-2.0.

The `sse2neon` submodule is required for `make crosscheck`. It is not required
for `make` or `make test`.

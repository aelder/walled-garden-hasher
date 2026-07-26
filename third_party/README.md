# Third-party sources

Only `make crosscheck` uses any of this. The miner itself — everything under
`src/`, `include/`, `net/`, `ui/` and `ref/` — is written from the VerusHash
2.2 specification and links none of it.

It is here because the cross-check is not optional. A reference transcribed
from the same misreading as the implementation agrees with it perfectly: that
is exactly how `clhash` case 4 passed 70,255 differential checks against this
project's own from-spec reference while reading the wrong Haraka round
constants. Only a diff against a *separately written* implementation caught it.
Vendoring these four files is the price of keeping that gate.

| Path | Origin | Licence |
|---|---|---|
| `verus/verus_clhash.{cpp,h}` | Verus Coin, © 2018 Michael Toutonghi | Apache-2.0 |
| `verus/haraka.{c,h}` | © 2016 kste | MIT |
| `verus/sse2neon/` | DLTcollab/sse2neon, submodule | MIT |

Unmodified. Their own notices are in the file headers and, for sse2neon, in its
`LICENSE`.

Both Apache-2.0 and MIT are compatible with this project's GPL-3.0-or-later —
Apache-2.0 notably is *not* compatible with GPL-2.0, which is part of why v3
was chosen.

The sse2neon submodule is required only for the cross-check. `make` and
`make test` do not need it, and the Makefile says so rather than failing on a
missing header three levels down.

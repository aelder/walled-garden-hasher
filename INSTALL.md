# vh22-top

A VerusHash 2.2 miner for Apple silicon. CPU only, no dependencies, one binary.

Requires an Apple silicon Mac and a terminal at least 60x19. Truecolor helps —
the palette is the 1977 Apple logo sampled from the logo itself, and it does
not degrade gracefully to ANSI 16.

## Verify what you downloaded, then unquarantine it

The binary is **not signed or notarized**. macOS quarantines anything arriving
from a browser, so Gatekeeper will refuse to run it: *"cannot be opened because
the developer cannot be verified"*.

Check the download against its published checksum first. Stripping quarantine
is telling macOS you vouch for this file, so it is worth being sure it is the
file that was built:

```bash
shasum -a 256 -c vh22-top-*.tar.gz.sha256
```

That must print `OK`. If it does not, stop — do not run the binary.

Then unpack and clear the quarantine flag:

```bash
tar xzf vh22-top-*-macos-arm64.tar.gz
cd vh22-top-*-macos-arm64
xattr -d com.apple.quarantine vh22-top
./vh22-top
```

`xattr -d com.apple.quarantine` removes the marker macOS attaches to
downloaded files. Do it only for files you have checksummed, and never as a
blanket habit.

Prefer not to? Build from source instead — it is one command and no quarantine
is involved:

```bash
cd vh22 && make top
```

## First run

It asks for two things once: the address rewards are paid to, and a name for
this machine on the pool. Everything after that is a list.

Pick a pool and it is tested immediately — by the time you are back on the
dashboard the panel says whether the endpoint is any good, and names the
address it actually resolved to. MINE only becomes available once the pool is
verified *and* holding work, so the button is never offered for a session that
could only produce zero.

If something is wrong the panel says what, and keeps saying it: the status row
reports what the client is doing this second, and a separate `⚠` row holds the
last actual failure, because a retry cycle spends most of its time saying
"connecting".

## Keys

| Key | Does |
|---|---|
| `↑` `↓` | move between controls |
| `←` `→` | adjust threads and lanes |
| `⏎` | select, or start and stop |
| `+` `-` | refresh rate: 100ms, 300ms, freeze |
| `i` | set the payout address |
| `e` `n` `d` | edit, add, delete a pool (in the pool list) |
| `q` | quit |

## Files

| Path | What |
|---|---|
| `~/.config/vh22/config` | identity and pools, mode 0600 — it names the wallet being mined to |
| `~/.config/vh22/news.md` | ticker copy, if you want your own; `$VH22_NEWS` overrides |

No wallet and no private key are stored, only the payout address.

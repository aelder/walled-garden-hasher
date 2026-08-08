# Install `vh22-top`

`vh22-top` requires an Apple silicon Mac and an interactive terminal at least
60 columns by 19 rows. Truecolor is recommended.

> [!WARNING]
> `vh22-top` is beta, free software provided without warranty. Mining places the
> CPU under sustained load and can increase heat, power use, battery drain, and
> hardware wear. Read [`DISCLAIMER.md`](DISCLAIMER.md) before installation or
> use.

## Install with Homebrew

```bash
brew install --cask aelder/tap/vh22-top && vh22-top
```

The cask supports Apple silicon and macOS 15 or later. It installs the prebuilt
release and bundled ticker data without compiling locally, so Xcode Command
Line Tools are not required.

Upgrade or uninstall it with:

```bash
brew upgrade --cask vh22-top
brew uninstall --cask vh22-top
```

## Install a release build manually

Download these two files for the same version from
[GitHub Releases](https://github.com/aelder/walled-garden-hasher/releases):

- `walled-garden-hasher-vX.Y.Z-macos-arm64.tar.gz`
- `walled-garden-hasher-vX.Y.Z-macos-arm64.tar.gz.sha256`

The binary is currently **unsigned and not notarized**. The steps below compare
the archive with its published checksum before removing the quarantine marker
that macOS adds to browser downloads.

The example below uses `v1.1.2`; replace it with the version you downloaded.

```bash
RELEASE=v1.1.2
ARCHIVE="walled-garden-hasher-${RELEASE}-macos-arm64.tar.gz"

shasum -a 256 -c "${ARCHIVE}.sha256"
tar xzf "${ARCHIVE}"
cd "${ARCHIVE%.tar.gz}"
```

`OK` confirms that the archive matches the published checksum. Any other result
indicates a mismatch.

After a successful checksum:

```bash
xattr -d com.apple.quarantine vh22-top
./vh22-top
```

`xattr -d com.apple.quarantine` removes the marker from the verified
`vh22-top` binary. No broader Gatekeeper or quarantine changes are required.

## Build from source

Install the Xcode Command Line Tools if needed:

```bash
xcode-select --install
```

Then clone, build, and launch:

```bash
git clone https://github.com/aelder/walled-garden-hasher.git
cd walled-garden-hasher
make top
```

The default build does not require submodules. Contributors running the
independent correctness cross-check should also run:

```bash
git submodule update --init third_party/verus/sse2neon
make crosscheck
```

## First run

The miner asks for two identity values once:

1. The Verus payout address that receives rewards.
2. A rig name that identifies this Mac to the pool.

Next, choose a pool. The miner tests it immediately and enables mining only
after the endpoint is verified and has supplied work. The status row shows the
current connection phase, while the warning row retains the last actual error.

No wallet, private key, or seed phrase is stored. Only the payout address, rig
name, and pool settings are written to `~/.config/vh22/config` with mode `0600`.

## Keys

| Key | Action |
|---|---|
| `↑` / `↓` | Move between controls |
| `←` / `→` | Adjust threads and lanes |
| `Enter` | Select, start, or stop |
| `?` | Show the in-app key guide |
| `+` / `-` | Select 100 ms, 300 ms, or frozen graph refresh |
| `i` | Set the payout address |
| `e` / `n` / `d` | Edit, add, or delete a pool in the pool list |
| `q` | Quit |

## Files and overrides

| Path or variable | Purpose |
|---|---|
| `~/.config/vh22/config` | Identity and pools; mode `0600` |
| `~/.config/vh22/news.md` | Optional ticker copy |
| `VH22_NEWS` | Override the ticker file path |
| `~/.config/vh22/film` | Optional animation frames |
| `VH22_FILM` | Override the animation directory |

Run `./vh22-top --help` for the built-in summary.

## Troubleshooting

- **Homebrew stops before launching `vh22-top`:** the install and launch are
  joined with `&&`, so a failed install does not produce a second, misleading
  `command not found` error. Retry the Homebrew command above; the current cask
  installs a prebuilt binary and does not require Command Line Tools.
- **macOS says the developer cannot be verified:** verify the SHA-256 checksum,
  then remove quarantine from `vh22-top` as shown above.
- **The program says it needs an interactive terminal:** run it directly from
  Terminal, iTerm2, or another terminal emulator instead of redirecting input.
- **The interface says the window is too small:** resize the terminal to at
  least 60x19.
- **Mining is unavailable:** select a pool and wait for both verification and
  the first job. The status and warning rows explain connection failures.
- **CPU use is high:** this is expected while mining. Reduce the thread count
  in the interface or stop mining with `Enter`.

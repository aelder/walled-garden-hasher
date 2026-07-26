# Ticker copy

The headlines that scroll across the dashboard, between the header and the
hashrate plot. They run in this order and loop.

One headline per `- ` bullet, under `## live`. Bullets anywhere else in the
file are ignored, so notes and anything parked under `## spiked` cost nothing.

House style, so the ticker matches the rest of the UI: an em dash `—` for the
aside, never a spaced hyphen; one sentence, short enough to read in a single
pass at about ten seconds a screen; present tense, straight face.

Read at runtime, so editing this file and relaunching is enough — no rebuild.
It is looked for in `$VH22_NEWS`, then `~/.config/vh22/news.md`, then
`ui/news.md` and `news.md` relative to the working directory. A binary that
finds none of them falls back to the first headline below, compiled in.

## live

- Walled Garden Hasher released, bringing Verus mining to Apple Silicon — at least one person reportedly extremely excited.

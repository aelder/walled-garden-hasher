# Ticker copy

The headlines that scroll across the dashboard, between the header and the
hashrate plot. They run in this order and loop.

One headline per `- ` bullet, under `## live`. Bullets anywhere else in the
file are ignored, so notes and anything parked under `## spiked` cost nothing.

House style, so the ticker matches the rest of the UI: an em dash `—` for the
aside, never a spaced hyphen; one sentence; present tense, straight face.

Length is not a constraint — a headline wider than the window is split at a
word boundary and held a screen at a time, rather than truncated. It is still
worth landing the joke on the first screen where you can, since that is the one
someone glancing up will read.

Read at runtime, so editing this file and relaunching is enough — no rebuild.
It is looked for in `$VH22_NEWS`, then `~/.config/vh22/news.md`, then
`ui/news.md` and `news.md` relative to the working directory. A binary that
finds none of them falls back to the first headline below, compiled in.

## live

- Walled Garden Hasher released, bringing Verus mining to Apple Silicon — at least one person reportedly extremely excited.

- Tim Cook rumored to be seriously considering changing name to Tim Apple. Says it just, "feels magical, and more Tim than ever."

- Known Monetary Joker, Steve Wozniak, Urges Treasury to Release Limited-Edition $4.20 Bill With Built-In Prank Mode.

- Apple Reportedly Testing New Mouse Designed to Be Used Entirely Upside Down. Leaker Says Charging Port Has Also Been Moved to the Top.

- President of United States Floats Idea of Strategic RAM Reserve. Aide Says President Was Concerned He Wouldn’t Be Able to Play The Sims With All 97 Expansion Packs Installed.



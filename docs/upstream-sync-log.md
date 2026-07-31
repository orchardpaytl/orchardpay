# Upstream sync log

Tracks which `dashpay-upstream/v1.0-dev` (dashpay/dash-evo-tool) commits have made it into OrchardPay, and how each was verified. This is a living document, updated at the end of every sync check — not date-grouped like `docs/ai-design/**`. See `CLAUDE.md`'s "Syncing from upstream" section for the verification method this log implements.

## Why this exists

Diff/patch-id comparison against upstream is not trustworthy in this repo: the `dash_evo_tool::` → `orchardpay::` crate rename changes the diff bytes of nearly every non-trivial commit, and a meaningful fraction of upstream PRs land here through a **separate matching PR** (same title/PR number, no `cherry-pick -x` trailer) rather than an actual cherry-pick — so `git log --grep "cherry picked from"` alone undercounts what's already in. Each commit below was checked individually: first for a recorded cherry-pick trailer, then — where none existed — by grepping for the distinctive symbol/file/PR-title it introduces. This table is the persisted result of that work, so the next sync starts from "already known" instead of re-deriving it.

## How to run a sync check

1. `git fetch dashpay-upstream v1.0-dev`
2. `git log --oneline v1.0-dev..dashpay-upstream/v1.0-dev` — lists commits upstream has that we don't have *by hash*. This is a starting list, not a final one: some may already be applied under a different hash.
3. For each commit, check in order:
   - Does a local commit carry `(cherry picked from commit <hash>)` for it? (`git log --grep "cherry picked from commit <hash>"`)
   - If not: does `git log --oneline --all --grep "(#<PR number>)"` find a local commit with the same PR number/title? (Applied via a separate matching PR, no trailer.)
   - If still not found: grep for a distinctive symbol, type, or file path the commit introduces (see its `git show --stat`) across `src/` and `tests/`. Presence with a *different* introducing commit hash means it's already in; absence means it's new.
4. For genuinely new commits, cherry-pick in upstream chronological order (oldest first) with `git cherry-pick -x`, do the `dash_evo_tool::` → `orchardpay::` rename follow-up (`grep -rl "dash_evo_tool::" --include="*.rs" .`), then build/test/fmt/clippy per `CLAUDE.md`.
5. Append the newly-applied commits to the table below and update "Last checked".

**Last checked:** 2026-07-31, against `dashpay-upstream/v1.0-dev` @ `2ee9fa64` (2026-07-31).

## Applied commits

| Upstream hash | Title | Applied locally as | Notes |
|---|---|---|---|
| `62b804bc` | resolve key's private half by matching material (#946) | `f7a217e3` | cherry-pick |
| `06e64e77` | Key Info reachable everywhere (#945) | `e58dba7e` | cherry-pick |
| `76076221` | recover keys stranded by legacy migration (#941) | `15cc1c41` | cherry-pick |
| `3e05d5f3` | track platform PR #3968 branch (#940) | `cf4cc405` | cherry-pick |
| `86419a2a` | fix quinn-proto Dependabot alert (#938) | `1fb67b3d` | cherry-pick |
| `1bc590ed` | epoch-proof regression version ratchet (#936) | `d5e40f97` | cherry-pick |
| `cf68c050` | app review batch (#934) | `f082e4d6` | cherry-pick |
| `9841afe6` | bump platform pin to PR #3968 tip / seedless rehydration (#919) | `589c0a15` | separate matching PR |
| `60405ad5` | move alias rename into backend task (#932) | `2f97d124` | separate matching PR |
| `6c20946d` | allow triage-permission bot (#931) | `2b3799e3` | separate matching PR |
| `3dd9cdac` | centralize validation and fee-reserve hygiene (#927) | `18f5de03` | separate matching PR |
| `c96d1c15` | triage regression tests, Max-send repro (#924) | `06ef10af` | separate matching PR |
| `9e89afa5` | kittest coverage for SendScreen routing (#928) | `5b928b0d` | separate matching PR |
| `7e80e603` | DPNS indicator + `Typography::hint()` (#918) | `b9da2a7f` | separate matching PR |
| `e4383722` | `SA_ONSTACK` fatal-signal handler (#926) | `b6aba0d0` | separate matching PR |
| `bbeab93a` | remove refresh-mode toggle (#921) | `b9468055` | separate matching PR |
| `bc477e70` | isolate address-generation regression test (#922) | `8ea3d1ef` | separate matching PR |
| `c2e2c07f` | close two rounds of key-placement-resolution review findings (#948) | `a13d5869` | cherry-pick, 2026-07-31 sync |
| `51de9590` | use selector ceiling for asset-lock Max (#937) | `027f6623` | cherry-pick, 2026-07-31 sync — also moved the `platform-wallet`/`dash-sdk` pin from branch-tracking to a frozen `rev = a18bd158`, matching upstream's current pin style; see `project_platform_wallet_pin_watch` |
| `2ee9fa64` | stop epoch-fetch retry storm from exhausting the DAPI rate limit (#950) | `1ab22dff` | cherry-pick, 2026-07-31 sync |

## Not applicable

| Upstream hash | Title | Why skipped |
|---|---|---|
| — | — | (none yet — `6c20946d`, the one CI/bot-permission commit seen so far, turned out to already be mirrored via a matching local PR, so it's in the table above, not here) |

# OrchardPay `contactAnchor` deferred replace: trigger-timing iterations

Status: **implemented** (2026-07-30) — the shielded-sync-completed trigger described
below is live, and the wallet-restore gap described below is also closed (see
"Known gap" below). A follow-up cost fix is also in (see "Follow-up" below).

## Background: what this mechanism is for

`contactAnchor`'s `anchorData` field carries a `their_reference_id`. The side
that creates the anchor first (the **Initiator**) doesn't yet know the
counterparty's real reference ID, so it seeds a self-recognizable filler value
(its own identity ID) instead of `None` — otherwise an outside Platform
observer could tell Initiator and Acceptor apart just by which anchor starts
"incomplete" and later gets a real value written in. Finding 5 of the
2026-07-27 adversarial audit closed that hole: **both** sides schedule a
deferred replace after the same fixed delay
(`ANCHOR_REPLACE_DELAY_MS`, 10 hours — `model/orchardpay.rs`). The Initiator's
replace swaps the filler for the real value once known; the Acceptor's is a
pure re-seal (fresh AEAD nonce, unchanged content) purely so its anchor also
shows exactly one mutation after a delay, matching the Initiator's side.

The scheduling itself has never changed: a `ScheduledAnchorReplace` marker
(anchor document ID + its own real `$createdAt` + role) is written to local
KV once, right after that side's own anchor document first broadcasts
(`contact_anchor::initiate_contact` / `accept_contact`). What's changed twice
now is **when the app checks whether a scheduled marker is due and fires it**
— `contact_anchor::fire_due_scheduled_anchor_replace` itself is unchanged
across all three iterations below.

## Iteration 1 (original): cold-boot/unlock catch-up pass

**What it did**: `AppContext::fire_due_scheduled_anchor_replaces` (in
`context/wallet_lifecycle/bootstrap.rs`) ran inside
`bootstrap_wallet_addresses_jit` — i.e. once at literal app process start, and
once on an explicit wallet-unlock gesture. It looped every locally-known
identity, every one of that identity's OrchardPay contacts, and checked each
one's marker.

**Why it failed**: confirmed empirically, not just theoretically, from a live
user's app logs spanning 13+ restarts over two days. **Every single attempt**
failed with the identical error: `"The network is still syncing. Please wait
a moment and try again."` The check ran immediately after the SDK object was
constructed — before there was any guarantee Platform/DAPI connectivity was
actually up, since the real replace requires a live `Document::fetch`. Direct
inspection of the local KV store (`platform-wallet.sqlite`) confirmed three
`ScheduledAnchorReplace` markers sitting unfired for 1+ days, each well past
the 10-hour threshold, none ever cleared.

A second, independent problem: since there is no periodic timer at all, an
app left running continuously past the 10-hour mark got **no further
chances** — the check only ever ran at those two discrete lifecycle events.

## Iteration 2: OrchardPay-tab-selection (`on_enter`)

**What it did**: added a new `ScreenLike::on_enter()` trait method, called
only when `AppState::select_main_screen` performed a **genuine** root-tab
switch (not a subscreen click within an already-active tab, and not a
`screen_stack` push/pop) — the natural counterpart to the existing
`on_leave()`. `OrchardPayScreen` set a `pending_anchor_replace_sweep` flag in
its `on_enter` override, drained by `ui()` into a `BackendTask` dispatch for
just the identity currently being viewed.

**Why it also failed**: `AppAction`'s `BitOrAssign` impl is **last-write-wins,
not a merge** —

```rust
fn bitor_assign(&mut self, rhs: Self) {
    if matches!(rhs, AppAction::None) { return; }
    *self = rhs;  // unconditionally replaces whatever action already held
}
```

`OrchardPayScreen::ui()` accumulates `action |= …` many times per frame,
including `action |= island_central_panel(ui, |ui| { …renders the active
subscreen… })` — which runs *after* the sweep's own dispatch. If that
subscreen's own render returned any non-`None` action the same frame, it
silently replaced the sweep's dispatch before `AppState` ever saw it. Live
logs confirmed the exact failure mode: `on_enter` fired, the dispatch was
constructed and logged — but the backend task itself never ran (no
document-fetch query in the log, no matching marker change in the KV store).

**Patch attempted, then abandoned**: moved the dispatch to the literal last
`action |=` write in `ui()`, guaranteeing nothing later in the function could
clobber it. This worked in principle, but it's a position-dependent fix (any
future code added after it in that large function silently reintroduces the
same class of bug) and it still tied correctness to a UI-navigation event at
all.

## Iteration 3 (current): piggyback on `OrchardPayShieldedSyncCompleted`

**What it does**: removed `on_enter` (and the trait method itself — unused
anywhere else) entirely. `app.rs`'s existing task-result handler for
`BackendTaskSuccessResult::OrchardPayShieldedSyncCompleted(seed_hashes)` —
which already dispatches `OrchardPayTask::ScanForIncomingAnchors` for the
DET-side memo-detection scan — now *also* dispatches
`OrchardPayTask::FireDueScheduledAnchorReplaces` for every locally-known
identity on each synced wallet, on the exact same event.

**Why this is a genuine improvement, not just a different workaround**:

- **Reliability**: this event fires automatically roughly every 60–70 seconds
  (the wallet's own shielded-sync cadence), with zero dependency on what the
  user clicks or which screen (if any) is open.
- **Network readiness is structural, not probabilistic**: the event only
  exists once a shielded sync pass has *already completed successfully* — the
  "network still syncing" race from iteration 1 is no longer just less likely,
  it's impossible by construction.
- **Immune to the `AppAction` clobbering bug**: dispatched via
  `self.handle_backend_task(...)` directly inside `app.rs`'s task-result
  handler, never touching `ui()`'s single-slot `action` accumulator at all.
  This isn't a narrower workaround for iteration 2's bug — it sidesteps the
  entire class of bug.
- **Net simpler despite doing more**: no new trait method, no per-screen
  pending-flag, no position-dependent ordering comment to maintain — and it
  now covers *every* identity on the wallet each pass, not just whichever one
  happened to be visible on screen.

### Files touched by this iteration

- `context/wallet_lifecycle/bootstrap.rs` — old cold-boot sweep method removed.
- `backend_task/orchardpay/contact_anchor.rs` —
  `fire_due_scheduled_anchor_replaces_for_identity` (per-identity sweep;
  logic unchanged from what iteration 1/2 already had, just relocated).
- `backend_task/orchardpay.rs` — `OrchardPayTask::FireDueScheduledAnchorReplaces`
  variant + dispatch arm.
- `app.rs` — the new call site inside the `OrchardPayShieldedSyncCompleted`
  handler.
- `model/orchardpay.rs` — doc comment describing the trigger.

## Known gap (now closed): wallet restore into a brand-new install

**Does this cover "I restore my wallet into a fresh app install with no local
state — will my contacts' pending anchor replaces still fire correctly?"**

**Status: closed.** At the time this doc was first written, the answer was
no — this section originally documented an open gap. It's since been fixed;
the original problem description and fix are kept below for the record.

`contact_anchor::recover_own_anchors` ("Recover from Network") is the
existing recovery path: it fetches every `contactAnchor` document the
identity has ever published, decrypts `anchorData`, and — for anything not
already tracked locally — reconstructs `OrchardPayContactState`
(`PendingOutbound` or `Established`). This part works fine after a restore:
contacts do come back.

**What it does *not* do**: write a `ScheduledAnchorReplace` marker for any
recovered anchor. Since the new (and old) trigger's *only* signal for "does
this relationship still need its deferred replace" is the presence of that
local marker, a wallet restored into a fresh install has **no markers at
all** — every recovered relationship, whether or not its anchor still
carries the unswapped filler `their_reference_id`, will silently never be
checked, forever. There's no error and no log line; the per-identity sweep
just finds nothing to do for that counterparty and moves on.

This isn't merely cosmetic. An unswapped filler on the Initiator side is
*exactly* the Initiator/Acceptor "tell" finding 5's whole delayed-replace
scheme was built to eliminate — so an anchor stuck this way after a restore
quietly reopens that fingerprinting gap for that specific relationship, with
no local signal that anything is wrong.

**Fix implemented**: `recover_own_anchors` now re-seeds a `ScheduledAnchorReplace`
marker for each newly-recovered anchor, using two signals it already had in
hand — no new network calls:

- `document.revision()` (`Some(1)` at creation, bumped by
  `fire_due_scheduled_anchor_replace`'s `bump_revision()` when the deferred
  replace fires): `revision > 1` means the replace has already happened —
  regardless of role — so no marker is written.
- At `revision == 1` (never replaced), `anchor_record.their_reference_id`
  disambiguates role: filler or `None` (legacy pre-fix anchor) → Initiator; a
  real value already present at revision 1 can only be an Acceptor anchor (an
  Initiator's real value only ever appears *after* a replace, which would
  have bumped the revision).

The marker's `anchor_created_at` uses the anchor's own real
`document.created_at()`, never recovery time, so the 10-hour clock is still
measured from when the anchor actually was created. Once written, the
existing periodic sweep (piggybacked on `OrchardPayShieldedSyncCompleted`)
picks it up and fires it exactly like any other marker — no changes needed
there. Scheduling only happens for genuinely new contacts (the existing
`already_tracked` early-continue already guards this), so it can never
clobber an in-flight marker a non-recovery flow is already tracking.

## Follow-up: bounding the sweep's per-tick cost (2026-07-30)

A separate sidecar-KV overload audit (prompted by an unrelated key-length bug fixed the
same day, `ab30b81b`) flagged that `fire_due_scheduled_anchor_replaces_for_identity`
enumerated **every** OrchardPay contact of an identity on every sweep tick — one
`orchardpay_get_scheduled_anchor_replace` KV read per contact, every ~60-70s, for every
locally-known identity across every loaded wallet (`load_local_user_identities` reads the
Global identity-index, not just the "selected" identity) — even though the overwhelming
majority of contacts never have a marker at all. Cost scaled with total contact count,
unbounded, with no cap analogous to `scan_for_incoming_anchors`'s
`MEMO_SCAN_ERROR_RETRY_CAP`.

**Fix**: added `WalletBackend::orchardpay_list_scheduled_anchor_replace_counterparties`
(`wallet_backend/orchardpay.rs`), which lists directly under the
`KV_PREFIX_SCHEDULED_ANCHOR_REPLACE` prefix instead of deriving candidates from the full
contact list — mirroring the existing `contact_key_prefix`/`orchardpay_list_contacts`
pattern. `fire_due_scheduled_anchor_replaces_for_identity` now sources counterparties from
this marker-only listing.

This is a pure optimization, not a design change: as established above, marker
*presence* was already the sole signal this mechanism acts on, regardless of whether the
marker was seeded by a live handshake (`initiate_contact`/`accept_contact`) or by this
doc's own wallet-restore re-seed path (`recover_own_anchors`) — both write through the
identical `orchardpay_set_scheduled_anchor_replace` accessor and key shape, so listing by
KV prefix sees both provenances identically. It also makes the post-recovery case
cheaper: right after a large restore, the sweep only touches the freshly re-seeded
markers, not every recovered contact. Covered by
`scheduled_anchor_replace_listing_only_returns_counterparties_with_markers` and
`scheduled_anchor_replace_listing_does_not_care_about_marker_provenance`
(`wallet_backend/orchardpay.rs` test module).

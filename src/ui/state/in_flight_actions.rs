//! Generic per-key "action already running" guard.
//!
//! Generalizes the `HashMap<Identifier, Instant>` guard pattern proven at
//! [`crate::ui::state::contacts_view::ContactsState`] (DashPay's Identity
//! Hub) so screens with their own independent list rows — each row's own
//! paid/mutating action, tracked separately — don't need to hand-roll the
//! same map. A screen with only one action in flight at a time (e.g. a
//! single conversation thread) doesn't need this at all: a plain `bool`
//! already covers it, since there's nothing to key by.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Threshold for surfacing an unusually long-running action. A guard is
/// never auto-released purely by elapsed time — only [`InFlightActions::release`]
/// or [`InFlightActions::clear`] does that — so a lost result can't silently
/// re-enable a row; [`InFlightActions::prune_stale`] is the deliberate,
/// screen-driven escape hatch for that case (e.g. called from a `refresh()`).
const IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Tracks which keys have an action currently running, keyed by whatever
/// identifies a row (contact `Identifier`, document `Identifier`, etc.).
/// Renders nothing — the owning screen reads [`InFlightActions::is_in_flight`]
/// to decide a row's own disabled state.
#[derive(Debug, Clone)]
pub struct InFlightActions<K> {
    in_flight: HashMap<K, Instant>,
}

impl<K> Default for InFlightActions<K> {
    // Not `#[derive(Default)]`: that would add a spurious `K: Default` bound,
    // since the derive macro applies bounds to every generic parameter
    // regardless of whether the field type actually needs them.
    fn default() -> Self {
        Self {
            in_flight: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash + Copy> InFlightActions<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim the in-flight slot for `key`. `true` means the caller owns the
    /// dispatch; `false` means an action for that key is already running and
    /// the caller must not dispatch a second one.
    #[must_use]
    pub fn begin(&mut self, key: K) -> bool {
        if self.is_in_flight(&key) {
            return false;
        }
        self.in_flight.insert(key, Instant::now());
        true
    }

    /// Whether an action for this key is already running. Drives the row's
    /// disabled state, so the user sees why the button does not respond.
    pub fn is_in_flight(&self, key: &K) -> bool {
        self.in_flight.contains_key(key)
    }

    /// Whether an authoritative result has taken unusually long to arrive.
    pub fn is_taking_long(&self, key: &K) -> bool {
        self.in_flight.get(key).is_some_and(|started| {
            Instant::now().saturating_duration_since(*started) >= IN_FLIGHT_TIMEOUT
        })
    }

    /// Release one key's guard, e.g. once its matching result has been
    /// confirmed (by re-checking real state) to have landed.
    pub fn release(&mut self, key: &K) {
        self.in_flight.remove(key);
    }

    /// Release every currently-tracked guard. Used where a result can't be
    /// correlated back to the one key that caused it (e.g. a generic error
    /// with no typed key attached) — blocking retry forever would be worse
    /// than the rare case of releasing an unrelated key's guard early.
    pub fn clear(&mut self) {
        self.in_flight.clear();
    }

    /// Keys currently tracked as in flight, for callers that need to
    /// re-validate each one against real state (see `release`'s doc comment).
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.in_flight.keys()
    }

    /// Drop guards older than [`IN_FLIGHT_TIMEOUT`] — a belt-and-suspenders
    /// cleanup for a result that never arrived (e.g. the app was closed
    /// mid-request). Call from a screen's own `refresh()`.
    pub fn prune_stale(&mut self) {
        let now = Instant::now();
        self.in_flight
            .retain(|_, started| now.saturating_duration_since(*started) < IN_FLIGHT_TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_in_flight_only_once() {
        let mut guard = InFlightActions::new();

        assert!(guard.begin(1), "the first click owns the action");
        assert!(guard.is_in_flight(&1));
        assert!(
            !guard.begin(1),
            "a second click must not claim an action that is already running"
        );
        assert!(guard.begin(2), "the guard is per key, not global");
    }

    #[test]
    fn releasing_one_key_leaves_others_protected() {
        let mut guard = InFlightActions::new();
        assert!(guard.begin(1));
        assert!(guard.begin(2));

        guard.release(&1);

        assert!(!guard.is_in_flight(&1));
        assert!(guard.is_in_flight(&2));
    }

    #[test]
    fn clear_releases_every_key() {
        let mut guard = InFlightActions::new();
        assert!(guard.begin(1));
        assert!(guard.begin(2));

        guard.clear();

        assert!(!guard.is_in_flight(&1));
        assert!(!guard.is_in_flight(&2));
    }

    #[test]
    fn a_guard_older_than_the_timeout_still_blocks_dispatch_until_released() {
        let mut guard = InFlightActions::new();
        guard.in_flight.insert(
            1,
            Instant::now() - IN_FLIGHT_TIMEOUT - Duration::from_secs(1),
        );

        assert!(guard.is_in_flight(&1));
        assert!(guard.is_taking_long(&1));
        assert!(
            !guard.begin(1),
            "elapsed time alone must not permit a second dispatch"
        );
    }

    #[test]
    fn prune_stale_drops_only_expired_guards() {
        let mut guard = InFlightActions::new();
        guard.in_flight.insert(
            1,
            Instant::now() - IN_FLIGHT_TIMEOUT - Duration::from_secs(1),
        );
        assert!(guard.begin(2));

        guard.prune_stale();

        assert!(
            !guard.is_in_flight(&1),
            "a guard past the timeout must be pruned"
        );
        assert!(guard.is_in_flight(&2), "a fresh guard must survive pruning");
    }

    #[test]
    fn keys_lists_every_tracked_key() {
        let mut guard = InFlightActions::new();
        assert!(guard.begin(1));
        assert!(guard.begin(2));

        let mut keys: Vec<i32> = guard.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![1, 2]);
    }
}

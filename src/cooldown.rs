use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default cooldown window (seconds) for suppressing retriggers of the same
/// `(alertname, host, threadname)` tuple. 0 = disabled.
pub(crate) const DEFAULT_COOLDOWN_SECS: u64 = 1800;

// ── Cooldown suppression ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) enum CooldownState {
    InFlight,
    Completed(Instant),
}

pub(crate) type CooldownKey = (String, String, String);
pub(crate) type CooldownMap = std::sync::Mutex<HashMap<CooldownKey, CooldownState>>;

/// Why a claim was rejected.
#[derive(Debug)]
pub(crate) enum SuppressReason {
    InFlight,
    RecentlyCompleted { ago: Duration },
}

/// RAII guard for the cooldown slot. On success, call `complete()` to record
/// the investigation timestamp. On failure (drop without `complete()`), the
/// slot is cleared so that Alertmanager retries are not suppressed.
pub(crate) struct CooldownGuard<'a> {
    key: CooldownKey,
    map: &'a CooldownMap,
    completed: bool,
}

impl<'a> CooldownGuard<'a> {
    /// Transition to `Completed(now)` and consume the guard.
    pub(crate) fn complete(mut self) {
        {
            let mut locked = self.map.lock().unwrap_or_else(|e| e.into_inner());
            locked.insert(self.key.clone(), CooldownState::Completed(Instant::now()));
        }
        // ORDERING: `completed` must be set AFTER the insert returns. If `completed`
        // were true before the insert and the insert panicked, Drop would skip cleanup
        // and leave a stale `InFlight` entry permanently suppressing this key.
        self.completed = true;
    }
}

impl Drop for CooldownGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Investigation failed or panicked — clear the slot so retries
            // are not suppressed. We do NOT transition to Completed because
            // no annotation was posted.
            let mut locked = self.map.lock().unwrap_or_else(|e| e.into_inner());
            locked.remove(&self.key);
        }
    }
}

/// Attempt to claim the cooldown slot for the given key. Returns a guard on
/// success, or the reason the claim was rejected.
pub(crate) fn try_claim_cooldown(
    key: CooldownKey,
    map: &CooldownMap,
    window: Duration,
) -> Result<CooldownGuard<'_>, SuppressReason> {
    let mut locked = map.lock().unwrap_or_else(|e| e.into_inner());

    // Evict expired entries to prevent unbounded growth.
    locked.retain(|_, state| match state {
        CooldownState::InFlight => true,
        CooldownState::Completed(at) => at.elapsed() < window,
    });

    match locked.get(&key) {
        Some(CooldownState::InFlight) => Err(SuppressReason::InFlight),
        Some(CooldownState::Completed(at)) => {
            let ago = at.elapsed();
            // retain() above already evicted expired entries under the same lock,
            // so ago < window is always true here.
            Err(SuppressReason::RecentlyCompleted { ago })
        }
        None => {
            locked.insert(key.clone(), CooldownState::InFlight);
            Ok(CooldownGuard {
                key,
                map,
                completed: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cooldown_is_30_minutes() {
        assert_eq!(DEFAULT_COOLDOWN_SECS, 1800);
    }

    #[test]
    fn try_claim_succeeds_on_empty_map() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        let guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30));
        assert!(guard.is_ok());
        let locked = map.lock().unwrap();
        assert!(matches!(locked.get(&key), Some(CooldownState::InFlight)));
    }

    #[test]
    fn try_claim_suppresses_inflight() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
        let result = try_claim_cooldown(key, &map, Duration::from_secs(30));
        assert!(matches!(result, Err(SuppressReason::InFlight)));
    }

    #[test]
    fn try_claim_suppresses_completed_within_window() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(Instant::now()));
        let result = try_claim_cooldown(key, &map, Duration::from_secs(30));
        assert!(matches!(
            result,
            Err(SuppressReason::RecentlyCompleted { .. })
        ));
    }

    #[test]
    fn try_claim_allows_completed_beyond_window() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        let past = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(past));
        let result = try_claim_cooldown(key, &map, Duration::from_secs(1));
        assert!(result.is_ok());
    }

    #[test]
    fn try_claim_allows_different_key() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key_a = ("AlertA".to_string(), "host1".to_string(), String::new());
        let key_b = ("AlertB".to_string(), "host1".to_string(), String::new());
        let _guard_a = try_claim_cooldown(key_a, &map, Duration::from_secs(30)).unwrap();
        let result = try_claim_cooldown(key_b, &map, Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn try_claim_differentiates_by_threadname() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key_msghand = (
            "PeerObserverThreadSaturation".to_string(),
            "bitcoin-03".to_string(),
            "b-msghand".to_string(),
        );
        let key_net = (
            "PeerObserverThreadSaturation".to_string(),
            "bitcoin-03".to_string(),
            "b-net".to_string(),
        );
        let _guard = try_claim_cooldown(key_msghand, &map, Duration::from_secs(30)).unwrap();
        // Different threadname on the same host should not be suppressed
        let result = try_claim_cooldown(key_net, &map, Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn guard_complete_transitions_to_completed() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        let guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
        guard.complete();
        let locked = map.lock().unwrap();
        assert!(matches!(
            locked.get(&key),
            Some(CooldownState::Completed(_))
        ));
    }

    #[test]
    fn guard_drop_without_complete_clears_entry() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        {
            let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
            // guard drops here without complete()
        }
        let locked = map.lock().unwrap();
        assert!(locked.get(&key).is_none());
    }

    #[test]
    fn guard_panic_safety() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
            panic!("simulated failure");
        }));
        assert!(result.is_err());
        let locked = map.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            locked.get(&key).is_none(),
            "entry should be cleared after panic"
        );
    }

    #[test]
    fn cooldown_zero_does_not_suppress() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string(), String::new());
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(Instant::now()));
        let result = try_claim_cooldown(key, &map, Duration::ZERO);
        assert!(
            result.is_ok(),
            "zero cooldown should not suppress even a just-completed entry"
        );
    }
}

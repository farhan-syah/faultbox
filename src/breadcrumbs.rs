// SPDX-License-Identifier: MIT OR Apache-2.0

//! The flight recorder: a bounded, always-on, in-memory ring of recent
//! significant events, dumped into every report.
//!
//! This is the single highest-value component — it turns a non-reproducible
//! failure into a debuggable one by preserving the *operation sequence* that
//! led to it (commit ids, page allocs/frees, reopens, key ops). It is
//! deliberately cheap (a bounded `VecDeque` behind a `Mutex`, no allocation
//! beyond the fixed capacity's worth of records) so it can run in production.
//!
//! Recording never panics and never blocks meaningfully: on a poisoned lock it
//! silently drops the crumb rather than propagating failure out of a logging
//! call. Capacity is fixed at init; the oldest crumb is evicted on overflow.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// Severity of a breadcrumb, mirroring common log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// One recorded event in the flight recorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breadcrumb {
    /// Unix-epoch milliseconds when recorded.
    pub ts_ms: u128,
    pub level: Level,
    /// Coarse category, e.g. `"myapp.commit"`, `"myapp.free"`.
    pub category: String,
    /// Human message (should already avoid user data; the writer redacts too).
    pub message: String,
    /// Structured fields. Keep small and free of user content.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub fields: serde_json::Value,
    /// Which process recorded this crumb. `None` for crumbs from this process's
    /// own recorder (they are all this process); `Some` for crumbs read back
    /// from a shared, artifact-keyed ring, where the origin is the whole point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// The process-wide recorder. Bounded; oldest-evicted.
pub struct Recorder {
    ring: Mutex<VecDeque<Breadcrumb>>,
    capacity: usize,
}

impl Recorder {
    fn record(&self, crumb: Breadcrumb) {
        // Never let a logging call take down the caller: drop on poison.
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() == self.capacity {
                ring.pop_front();
            }
            ring.push_back(crumb);
        }
    }

    /// Snapshot the current trail oldest-first, without clearing it.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Breadcrumb> {
        self.ring
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default()
    }
}

static RECORDER: OnceLock<Recorder> = OnceLock::new();

/// Initialize the global recorder with a fixed capacity. Idempotent: a second
/// call is ignored (the first capacity wins), so competing `init`s are safe.
pub(crate) fn init(capacity: usize) {
    let _ = RECORDER.set(Recorder {
        ring: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
        capacity: capacity.max(1),
    });
}

/// The global recorder, if [`init`] has run.
#[must_use]
pub fn recorder() -> Option<&'static Recorder> {
    RECORDER.get()
}

/// Record a breadcrumb. A no-op if the recorder was never initialized, so
/// libraries can emit crumbs unconditionally without coupling to app setup.
///
/// When a shared, artifact-keyed ring is configured (`shared-ring` feature),
/// the crumb is written to it as well, so processes that later open the same
/// artifact can see what this one did.
pub fn record(
    level: Level,
    category: impl Into<String>,
    message: impl Into<String>,
    fields: serde_json::Value,
) {
    let Some(rec) = RECORDER.get() else { return };
    let category = category.into();
    let message = message.into();

    #[cfg(feature = "shared-ring")]
    if let Some(ring) = crate::config().and_then(|c| c.shared_ring.as_ref()) {
        ring.record(level, &category, &message);
    }

    rec.record(Breadcrumb {
        ts_ms: crate::now_ms(),
        level,
        category,
        message,
        fields,
        pid: None,
    });
}

/// Snapshot the current trail (oldest-first). Empty if uninitialized.
#[must_use]
pub fn snapshot() -> Vec<Breadcrumb> {
    RECORDER.get().map(Recorder::snapshot).unwrap_or_default()
}

/// Emit a breadcrumb ergonomically.
///
/// ```ignore
/// faultbox::breadcrumb!(Info, "myapp.commit", "committed", { "commit_id": 9557 });
/// faultbox::breadcrumb!(Warn, "myapp.free", "freed chain");
/// ```
#[macro_export]
macro_rules! breadcrumb {
    ($level:ident, $category:expr, $message:expr, $fields:tt) => {
        $crate::breadcrumbs::record(
            $crate::breadcrumbs::Level::$level,
            $category,
            $message,
            $crate::serde_json::json!($fields),
        )
    };
    ($level:ident, $category:expr, $message:expr) => {
        $crate::breadcrumbs::record(
            $crate::breadcrumbs::Level::$level,
            $category,
            $message,
            $crate::serde_json::Value::Null,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_evicts_oldest() {
        let rec = Recorder {
            ring: Mutex::new(VecDeque::new()),
            capacity: 3,
        };
        for i in 0..5 {
            rec.record(Breadcrumb {
                ts_ms: i as u128,
                level: Level::Info,
                category: "t".to_owned(),
                message: format!("m{i}"),
                fields: serde_json::Value::Null,
                pid: None,
            });
        }
        let snap = rec.snapshot();
        assert_eq!(snap.len(), 3, "capacity bound holds");
        // Oldest (m0, m1) evicted; newest three remain in order.
        assert_eq!(snap[0].message, "m2");
        assert_eq!(snap[2].message, "m4");
    }

    #[test]
    fn record_is_a_noop_when_uninitialized() {
        // Global recorder is not init'd in this unit-test process by default;
        // record must not panic and snapshot must be empty.
        record(Level::Error, "x", "y", serde_json::Value::Null);
        // (Cannot assert emptiness reliably if another test init'd it; just
        // assert the call is infallible.)
    }
}

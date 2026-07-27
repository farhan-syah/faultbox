// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contract when several *layers* of one dependency stack all use
//! `faultbox` — a storage engine, the database built on it, and the application
//! on top.
//!
//! This pins the answers to the questions that decide how adopters wire it up:
//! who may call [`faultbox::init`], whether a shared breadcrumb trail merges or
//! duplicates, and whether one root cause becomes one report or several.

use faultbox::{Adhoc, Capture, Config, EventKind};

/// The lowest layer — a storage engine that detects corruption itself.
mod storage {
    use super::*;

    /// A library must never call `init`: it does not own the process. It only
    /// records crumbs, which are inert until the binary initializes.
    pub fn commit(id: u64) {
        faultbox::breadcrumb!(Info, "storage.commit", "committed", { "commit_id": id });
    }

    /// The detection site: the layer that actually knows the invariant is the
    /// layer that reports it.
    pub fn detect_corruption() -> Option<std::path::PathBuf> {
        let ctx = Adhoc {
            kind: "storage.checksum",
            key: "class=checksum".to_owned(),
            value: serde_json::json!({ "page": 828 }),
        };
        Capture::new(EventKind::Corruption, "checksum mismatch on read")
            .domain(&ctx)
            .emit()
    }
}

/// The middle layer — a database built on the storage engine.
mod database {
    pub fn query() {
        faultbox::breadcrumb!(Info, "database.query", "scanning", { "table": "users" });
    }

    /// What an upper layer *should* do with an error from below: add context to
    /// the trail and propagate. Emitting here too would file a second report for
    /// the same root cause.
    pub fn propagate_without_reporting() {
        faultbox::breadcrumb!(Warn, "database.read", "read failed, propagating");
    }
}

#[test]
fn layers_share_one_recorder_one_trail_and_one_report_per_detection_site() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = tmp.path().join("reports");

    // Only the binary initializes, and it names *itself* — the process is the
    // app, even though the failure is detected several layers down.
    assert!(
        faultbox::init(
            Config::new("theapp", "0.1.0", &reports)
                .install_panic_hook(false)
                .features(["storage", "database"]),
        ),
        "the first init wins"
    );

    // A library calling init later changes nothing and reports its own failure
    // to take effect. This is why libraries must not call it.
    assert!(
        !faultbox::init(Config::new(
            "storage",
            "9.9.9",
            tmp.path().join("elsewhere")
        )),
        "a second init is refused, not merged"
    );

    // Interleaved work across all three layers.
    storage::commit(9557);
    database::query();
    storage::commit(9558);
    database::propagate_without_reporting();

    let dir = storage::detect_corruption().expect("the detection site reports");

    let group = faultbox::reader::load(&dir).unwrap();

    // ONE report for one root cause — the layer that detected it filed it.
    let all = faultbox::reader::list(&reports).unwrap();
    assert_eq!(all.len(), 1, "one detection site, one report group");
    assert_eq!(group.occurrences(), 1);

    // The report is attributed to the *process*, not the detecting library...
    assert_eq!(group.first.meta.project, "theapp");
    assert_eq!(
        group.first.meta.version, "0.1.0",
        "the losing init's version must not leak in"
    );
    // ...while `domain_kind` records which layer detected it.
    assert_eq!(
        group.first.domain_kind.as_deref(),
        Some("storage.checksum"),
        "the detecting layer is identified by its domain kind"
    );

    // Crumbs from every layer merge into ONE causal trail, in order. They are
    // not duplicated per layer — a crumb is recorded once, wherever it is
    // emitted from.
    let trail: Vec<&str> = group
        .first
        .breadcrumbs
        .iter()
        .map(|c| c.category.as_str())
        .collect();
    assert_eq!(
        trail,
        [
            "storage.commit",
            "database.query",
            "storage.commit",
            "database.read",
        ],
        "one interleaved trail across layers, each crumb exactly once"
    );

    // The whole point of the merge: the report filed by the storage layer
    // carries the database layer's context too.
    assert!(
        group
            .first
            .breadcrumbs
            .iter()
            .any(|c| c.category.starts_with("database.")),
        "a lower layer's report must still see upper-layer breadcrumbs"
    );
}

// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end: model the real pagedb corruption this crate was designed for —
//! record operation breadcrumbs, then capture a corruption report with domain
//! forensic context and a preserved snapshot of the bad store — and verify the
//! on-disk report is complete and reloadable.

use blackbox::{Capture, Config, DomainContext, EventKind, Report};

/// The forensic context pagedb would attach at the dangling-child detection
/// site (mirrors the real `pagedb-fsck` finding).
struct DanglingChild {
    parent: u64,
    child: u64,
    on_disk_kind: u8,
}

impl DomainContext for DanglingChild {
    fn domain_kind(&self) -> &'static str {
        "pagedb.dangling_child"
    }
    fn grouping_key(&self) -> String {
        // Groups by failure class, NOT the specific page ids.
        format!("child_kind=0x{:02x}", self.on_disk_kind)
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "parent_page": self.parent,
            "child_page": self.child,
            "child_on_disk_kind": format!("0x{:02x}", self.on_disk_kind),
            "interpretation": "internal btree child recycled as OverflowRoot — use-after-free",
        })
    }
}

#[test]
fn corruption_report_is_captured_with_context_breadcrumbs_and_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("crash-reports");

    // Init once (no panic hook in tests).
    assert!(blackbox::init(
        Config::new("pagedb", "0.1.0", &reports_dir)
            .git_sha("deadbeefcafe")
            .install_panic_hook(false),
    ));

    // Operation trail leading up to the failure — the flight recorder.
    blackbox::breadcrumb!(Info, "pagedb.reopen", "opened store", { "commit_id": 9557 });
    blackbox::breadcrumb!(Debug, "pagedb.free", "released overflow chain", { "root": 6050 });
    blackbox::breadcrumb!(Info, "pagedb.commit", "committed", { "commit_id": 9558 });

    // A fake corrupt store to preserve for offline fsck.
    let store = tmp.path().join("db");
    std::fs::create_dir_all(store.join("seg")).unwrap();
    std::fs::write(store.join("main.db"), b"corrupt pages").unwrap();

    let ctx = DanglingChild {
        parent: 6044,
        child: 6050,
        on_disk_kind: 0x09,
    };

    let dir = Capture::new(
        EventKind::Corruption,
        "internal node references page that is not a valid btree node",
    )
    .error_chain(["ChecksumFailure", "AEAD/MAC verification failed on read"])
    .domain(&ctx)
    .with_backtrace()
    .preserve(
        "pagedb-store",
        &store,
        "store.corrupt",
        Some("inspect with: pagedb-fsck <dir> --deep --realm 00..0".to_owned()),
    )
    .emit()
    .expect("report emitted");

    // report.json exists and reloads.
    let text = std::fs::read_to_string(dir.join("report.json")).unwrap();
    let report: Report = serde_json::from_str(&text).unwrap();

    assert_eq!(report.kind, EventKind::Corruption);
    assert_eq!(report.meta.project, "pagedb");
    assert_eq!(report.meta.git_sha.as_deref(), Some("deadbeefcafe"));
    assert_eq!(report.error_chain.len(), 2);

    // Domain forensic context survived.
    assert_eq!(report.domain["parent_page"], 6044);
    assert_eq!(report.domain["child_on_disk_kind"], "0x09");

    // The flight-recorder trail is present, oldest-first.
    assert_eq!(report.breadcrumbs.len(), 3);
    assert_eq!(report.breadcrumbs[0].category, "pagedb.reopen");
    assert_eq!(report.breadcrumbs[2].fields["commit_id"], 9558);

    // The corrupt store was copied in beside the report.
    assert_eq!(report.artifacts.len(), 1);
    assert_eq!(report.artifacts[0].kind, "pagedb-store");
    assert!(dir.join("store.corrupt/main.db").is_file());

    // Fingerprint is stable and groups by (site, failure class), independent of
    // the specific page ids or message — a different report at the same site
    // with the same child-kind must land in the same group.
    let fp_other_pages = blackbox::writer::fingerprint(
        "pagedb",
        EventKind::Corruption,
        "pagedb.dangling_child|child_kind=0x09",
        "some other message with page 999",
    );
    assert_eq!(report.fingerprint, fp_other_pages);
    assert_eq!(report.domain_kind.as_deref(), Some("pagedb.dangling_child"));
}

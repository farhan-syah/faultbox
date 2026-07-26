// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regression test for the failure mode that motivated coalescing.
//!
//! A supervised process that crashes on startup re-detects the same bug on
//! every restart. Writing one report directory per occurrence turns that into
//! thousands of directories with the same fingerprint and the same preserved
//! artifact copied into each — simultaneously a disk-exhaustion hazard on the
//! machine whose durability is already in question, and a triage problem, since
//! the number that matters ("this fired N times") is buried in a listing.
//!
//! The recorder must therefore turn N occurrences of one bug into one report
//! directory carrying `occurrences: N`, while still preserving exactly one copy
//! of the artifact.

use faultbox::{Capture, Config, DomainContext, EventKind};

struct DanglingChild {
    child_kind: u8,
    page: u64,
}

impl DomainContext for DanglingChild {
    fn domain_kind(&self) -> &'static str {
        "store.dangling_child"
    }
    fn grouping_key(&self) -> String {
        // Groups by failure class, deliberately NOT by page id.
        format!("child_kind=0x{:02x}", self.child_kind)
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "page": self.page })
    }
}

#[test]
fn a_crash_loop_collapses_into_one_group_with_an_occurrence_count() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("crash-reports");

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    // A corrupt store that gets re-detected on every reopen.
    let store = tmp.path().join("db");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("main.db"), vec![0xab; 4096]).unwrap();

    // The same bug detected 200 times, each hit naming a different page — the
    // volatile detail that must not split the group.
    const HITS: u64 = 200;
    let mut dirs = std::collections::HashSet::new();
    for i in 0..HITS {
        let ctx = DanglingChild {
            child_kind: 0x09,
            page: 6000 + i,
        };
        let dir = Capture::new(
            EventKind::Corruption,
            format!(
                "internal node references page {} which is not a btree node",
                6000 + i
            ),
        )
        .domain(&ctx)
        .preserve("store-snapshot", &store, "store.corrupt", None)
        .emit()
        .expect("report emitted");
        dirs.insert(dir);
    }

    assert_eq!(
        dirs.len(),
        1,
        "200 occurrences of one bug must share a single report directory"
    );

    // The directory listing agrees: one group, not 200.
    let groups = faultbox::reader::list(&reports_dir).unwrap();
    assert_eq!(groups.len(), 1);

    let group = &groups[0];
    assert_eq!(
        group.occurrences(),
        HITS,
        "the count that matters is preserved, not the directory count"
    );
    assert!(group.first.first_seen_ms <= group.first.last_seen_ms);
    assert_eq!(faultbox::reader::total_occurrences(&groups), HITS);

    // The first capture is kept verbatim; the most recent one is also available.
    assert!(group.first.message.contains("page 6000"));
    assert!(
        group.latest.is_some(),
        "a repeated bug records its latest hit"
    );
    assert!(
        group
            .most_recent()
            .message
            .contains(&format!("page {}", 6000 + HITS - 1))
    );

    // Exactly one copy of the 4 KiB store, not 200.
    assert!(group.dir.join("store.corrupt/main.db").is_file());
    assert_eq!(group.first.artifacts.len(), 1);
    assert_eq!(group.first.artifacts[0].bytes, Some(4096));
    let on_disk = dir_size(&group.dir);
    assert!(
        on_disk < 64 * 1024,
        "the whole group must stay small; 200 copies would be ~800 KiB, got {on_disk} bytes"
    );

    // The lock file is not left behind.
    assert!(!group.dir.join(".lock").exists());
}

fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            total += dir_size(&entry.path());
        } else if ft.is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

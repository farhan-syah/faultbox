// SPDX-License-Identifier: MIT OR Apache-2.0

//! If several layers of one stack each emit for the same underlying failure,
//! `faultbox` files a separate report for each — it cannot tell that they share
//! a root cause.
//!
//! This is the failure mode to design against: report at the detection site and
//! propagate elsewhere. Pinned here so the behaviour is a documented consequence
//! rather than a surprise in production.
//!
//! It lives in its own integration binary because [`faultbox::init`] is
//! once-per-process: two tests in one binary would race for the one init that
//! wins, and the loser would file its reports into the winner's directory.

use faultbox::{Adhoc, Capture, Config, EventKind};

#[test]
fn each_emit_is_its_own_report_faultbox_cannot_infer_a_shared_root_cause() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = tmp.path().join("reports");
    assert!(
        faultbox::init(Config::new("theapp", "0.1.0", &reports).install_panic_hook(false)),
        "this binary's only init must win, or the reports land elsewhere"
    );

    // Same underlying bad page, reported by two layers on the way up.
    for (kind, key) in [
        ("storage.checksum", "class=checksum"),
        ("database.read", "class=io"),
    ] {
        let ctx = Adhoc {
            kind,
            key: key.to_owned(),
            value: serde_json::Value::Null,
        };
        let _ = Capture::new(EventKind::Corruption, "read failed")
            .domain(&ctx)
            .emit();
    }

    let groups = faultbox::reader::list(&reports).unwrap();
    assert_eq!(
        groups.len(),
        2,
        "two emits for one root cause produce two groups; dedup is the \
         adopter's job, by only reporting at the detection site"
    );
}

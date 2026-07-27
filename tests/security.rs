// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regressions for the ways a report could leak, escape, or be tampered with.
//!
//! Each of these was a real defect found in an audit, not a hypothetical. They
//! live together because they share one property: the failure is silent. A
//! world-readable minidump, a backtrace that skipped the redactor, and an
//! artifact name that escaped the reports directory all produce a report that
//! looks exactly like a correct one.
//!
//! Every test calls `faultbox::init`, which is once-per-process by design —
//! `cargo nextest` gives each test its own process, which is why the suite runs
//! under it (see `.config/nextest.toml`).

use faultbox::{Capture, Config, EventKind, Redactor, Report};

/// A redactor that marks everything it is given, so a test can prove a field
/// went through it. A pattern-matching redactor could only prove that a
/// *particular* secret was caught; this proves the field is wired to the seam
/// at all, which is what the bypasses were.
struct MarkEverything;

impl Redactor for MarkEverything {
    fn redact(&self, input: &str) -> String {
        format!("R:{input}")
    }
}

fn load(dir: &std::path::Path) -> Report {
    let text = std::fs::read_to_string(dir.join("report.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A report directory holds a verbatim copy of the adopter's data. On a
/// multi-user host the umask default (`0755`/`0644`) hands it to every local
/// account.
#[cfg(unix)]
#[test]
fn reports_and_preserved_artifacts_are_not_readable_by_other_accounts() {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;

    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    let file_artifact = tmp.path().join("main.db");
    std::fs::write(&file_artifact, b"user rows").unwrap();
    let dir_artifact = tmp.path().join("store");
    std::fs::create_dir_all(dir_artifact.join("seg")).unwrap();
    std::fs::write(dir_artifact.join("seg/s0"), b"user pages").unwrap();
    // A source the adopter left world-readable: the copy must not inherit it.
    std::fs::set_permissions(
        dir_artifact.join("seg/s0"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    let dir = Capture::new(EventKind::Corruption, "corrupt store")
        .preserve("db", &file_artifact, "main.db", None)
        .preserve("store", &dir_artifact, "store.snap", None)
        .emit()
        .expect("report written");

    assert_eq!(mode(&reports_dir), 0o700, "reports directory");
    assert_eq!(mode(&dir), 0o700, "group directory");
    assert_eq!(mode(&dir.join("report.json")), 0o600, "report.json");
    assert_eq!(mode(&dir.join("main.db")), 0o600, "preserved file");
    assert_eq!(mode(&dir.join("store.snap")), 0o700, "preserved directory");
    assert_eq!(
        mode(&dir.join("store.snap/seg/s0")),
        0o600,
        "a world-readable source must not stay world-readable in the report"
    );

    // Nothing left behind from staging, at any mode.
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".incoming.") || n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "staging paths leaked: {leftovers:?}");
}

/// The artifact name is joined onto the report directory, and committing an
/// artifact *removes* whatever is at the destination first — so an unchecked
/// name both wrote and deleted outside the reports directory.
#[test]
fn an_artifact_name_cannot_escape_the_report_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    let src = tmp.path().join("main.db");
    std::fs::write(&src, b"payload").unwrap();

    // A bystander file that a traversing name would have destroyed.
    let bystander = tmp.path().join("precious.db");
    std::fs::write(&bystander, b"do not touch").unwrap();

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    let dir = Capture::new(EventKind::Corruption, "traversal attempt")
        .preserve("db", &src, "../../escaped.db", None)
        .preserve("db", &src, "../precious.db", None)
        .emit()
        .expect("the capture still succeeds");

    assert!(
        !tmp.path().join("escaped.db").exists(),
        "the artifact must not be written outside the reports directory"
    );
    assert_eq!(
        std::fs::read(&bystander).unwrap(),
        b"do not touch",
        "a traversing name must not delete or overwrite an existing file"
    );

    // The refusal is on the report, not silent: an analyst has to know the
    // snapshot is missing.
    let report = load(&dir);
    assert_eq!(report.artifacts.len(), 2);
    for artifact in &report.artifacts {
        assert!(artifact.rel_path.is_empty(), "nothing was preserved");
        let note = artifact.note.as_deref().unwrap_or_default();
        assert!(note.contains("NOT PRESERVED"), "note was {note:?}");
    }
}

/// The recorder's own files share the directory with artifacts. A name of
/// `report.json` or `.lock` would have overwritten the report being written, or
/// the lock protecting it.
#[test]
fn an_artifact_cannot_claim_one_of_the_recorders_own_names() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");
    let src = tmp.path().join("main.db");
    std::fs::write(&src, b"payload").unwrap();

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    let dir = Capture::new(EventKind::Corruption, "reserved name")
        .preserve("db", &src, "report.json", None)
        .preserve("db", &src, ".lock", None)
        .emit()
        .expect("report written");

    // The report is intact and parseable — it was not overwritten by the
    // artifact that tried to claim its name.
    let report = load(&dir);
    assert_eq!(report.message, "reserved name");
    assert!(
        report.artifacts.iter().all(|a| a.rel_path.is_empty()),
        "a reserved name must be refused"
    );
}

/// The backtrace was the one report field that never reached the redactor. It
/// is rendered text, and what it renders is the build machine's absolute source
/// paths.
#[test]
fn the_backtrace_and_thread_name_go_through_the_redactor() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir)
            .install_panic_hook(false)
            .redactor(Box::new(MarkEverything)),
    ));

    let dir = std::thread::Builder::new()
        .name("tenant-acme-worker".to_owned())
        .spawn(|| {
            Capture::new(EventKind::InvariantViolation, "invariant broken")
                .with_backtrace()
                .emit()
                .expect("report written")
        })
        .unwrap()
        .join()
        .unwrap();

    let report = load(&dir);
    assert!(
        !report.backtrace.is_empty(),
        "this test is meaningless without frames"
    );
    for frame in &report.backtrace {
        if let Some(symbol) = &frame.symbol {
            assert!(
                symbol.starts_with("R:"),
                "a backtrace frame bypassed the redactor: {symbol:?}"
            );
        }
        if let Some(location) = &frame.location {
            assert!(location.starts_with("R:"), "frame location bypassed it");
        }
    }
    assert_eq!(
        report.meta.thread.as_deref(),
        Some("R:tenant-acme-worker"),
        "a thread name names the work it was spawned for"
    );
}

/// Artifact notes are assembled *after* the redaction pass and interpolate the
/// artifact's source path — an absolute path under the user's home.
#[test]
fn an_artifact_note_goes_through_the_redactor() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    let big = tmp.path().join("enormous.db");
    std::fs::write(&big, vec![0u8; 4096]).unwrap();

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir)
            .install_panic_hook(false)
            .preserve_max_bytes(16)
            .redactor(Box::new(MarkEverything)),
    ));

    let dir = Capture::new(EventKind::Corruption, "too big to keep")
        .preserve(
            "db",
            &big,
            "enormous.db",
            Some("the whole store".to_owned()),
        )
        .emit()
        .expect("report written");

    let report = load(&dir);
    let note = report.artifacts[0].note.as_deref().expect("a note");
    assert!(
        note.starts_with("R:"),
        "the note embeds the source path and must be redacted: {note:?}"
    );
}

/// Redaction walks adopter-built JSON recursively, from inside the panic hook,
/// so the walk is bounded at `MAX_JSON_DEPTH` and anything deeper is masked
/// wholesale rather than descended into.
///
/// The nesting here is deliberately modest — a few multiples of the bound, not
/// thousands of levels. Depth beyond that stops testing faultbox at all:
/// `serde_json::Value` builds and *drops* recursively, so a value deep enough to
/// exhaust the stack could never have been constructed for us to receive in the
/// first place. An earlier version of this test used 5000 levels and died in
/// `serde_json`'s own `Drop` — on a runner with a smaller stack than the machine
/// it was written on, which is exactly the flake that teaches nothing.
///
/// What faultbox owns is that *its* walk adds a bounded amount of depth on top
/// of whatever the adopter's structure already costs. That is what this asserts.
#[test]
fn nesting_past_the_bound_is_masked_and_shallow_payloads_survive_intact() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir)
            .install_panic_hook(false)
            .redactor(Box::new(faultbox::BasicRedactor::new().home("/home/ada"))),
    ));

    let depth = faultbox::redact::MAX_JSON_DEPTH as usize * 4;
    let mut deep = serde_json::json!({ "leaf": "sk-live-4242deadbeef4242" });
    for _ in 0..depth {
        deep = serde_json::json!({ "next": deep });
    }

    let ctx = faultbox::Adhoc {
        kind: "store.deep",
        key: "class=1".to_owned(),
        // A shallow sibling that must come through untouched, so the bound is
        // shown to be a ceiling rather than a blanket.
        value: serde_json::json!({ "page_id": 828, "buried": deep }),
    };

    let dir = Capture::new(EventKind::Corruption, "deeply nested context")
        .domain(&ctx)
        .emit()
        .expect("report written");

    let report = load(&dir);
    let text = serde_json::to_string(&report.domain).unwrap();

    assert!(
        !text.contains("sk-live-4242deadbeef4242"),
        "a subtree too deep to walk must be masked, never emitted: {text}"
    );
    assert!(
        text.contains(faultbox::redact::REDACTED_DEPTH),
        "the depth bound must be what stopped it, and must say so: {text}"
    );
    assert_eq!(
        report.domain["page_id"], 828,
        "an ordinary field beside the deep one is untouched"
    );
}

/// A redactor that panics on the string it is supposed to clean.
struct PanickingRedactor;

impl Redactor for PanickingRedactor {
    fn redact(&self, _input: &str) -> String {
        panic!("the adopter's redactor is broken");
    }
}

/// A recorder that takes the process down is worse than no recorder. The
/// capture path runs adopter code — the redactor, on every string — so "never
/// panics" is not something avoiding `unwrap` in this crate can deliver on its
/// own.
#[test]
fn a_panicking_redactor_does_not_take_the_process_down_or_leak() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir)
            .install_panic_hook(false)
            .redactor(Box::new(PanickingRedactor)),
    ));

    // Recording a crumb is a logging-shaped call on a hot path; it must survive
    // a broken redactor rather than propagating the panic to the caller.
    faultbox::breadcrumb!(Info, "myapp.commit", "committed sk-live-4242deadbeef");

    let out = Capture::new(EventKind::Corruption, "secret sk-live-4242deadbeef")
        .error_chain(["also sk-live-4242deadbeef"])
        .emit();

    assert!(
        out.is_none(),
        "a capture that could not be redacted must be abandoned, not written"
    );

    // And nothing half-redacted reached the disk: a missing report costs a
    // debugging session, a half-redacted one costs the secret.
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&reports_dir) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("report.json")) {
                found.push(text);
            }
        }
    }
    for text in &found {
        assert!(
            !text.contains("sk-live-4242deadbeef"),
            "an unredacted secret was written: {text}"
        );
    }
}

/// A `DomainContext` reaches into the very structures whose corruption is being
/// reported, so it is the implementation most likely to panic in exactly the
/// process that is already failing.
struct PanickingContext;

impl faultbox::DomainContext for PanickingContext {
    fn domain_kind(&self) -> &'static str {
        "store.broken"
    }
    fn grouping_key(&self) -> String {
        panic!("indexing a corrupt structure");
    }
    fn to_json(&self) -> serde_json::Value {
        panic!("indexing a corrupt structure");
    }
}

#[test]
fn a_panicking_domain_context_still_produces_a_report() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    let dir = Capture::new(
        EventKind::Corruption,
        "detected at a site with broken context",
    )
    .domain(&PanickingContext)
    .emit()
    .expect("the detection site still gets a report");

    let report = load(&dir);
    assert_eq!(report.message, "detected at a site with broken context");
    assert!(
        report.domain.is_null(),
        "the payload is dropped, not fabricated"
    );
}

/// The artifact digest is published as evidence the artifact arrived unaltered,
/// and it decides whether a later occurrence may reuse the snapshot on disk. A
/// 64-bit non-cryptographic hash supports neither claim.
#[test]
fn artifact_digests_are_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let reports_dir = tmp.path().join("reports");

    let src = tmp.path().join("abc.db");
    std::fs::write(&src, b"abc").unwrap();

    assert!(faultbox::init(
        Config::new("myapp", "0.1.0", &reports_dir).install_panic_hook(false)
    ));

    let dir = Capture::new(EventKind::Corruption, "digest check")
        .preserve("db", &src, "abc.db", None)
        .emit()
        .expect("report written");

    let report = load(&dir);
    let digest = report.artifacts[0].digest.as_deref().expect("a digest");
    assert_eq!(
        digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "a single-file artifact's digest is SHA-256 of its bytes"
    );
}

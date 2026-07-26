// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading back what the recorder wrote.
//!
//! Capturing a report is only half of the job — something has to *show* it.
//! This module is the consumer-facing half: a CLI, a support script, or an
//! admin UI can enumerate a reports directory, rank groups by how often each
//! bug is firing, and render a triage summary without re-deriving the on-disk
//! layout or hand-rolling JSON parsing.
//!
//! ```no_run
//! for group in faultbox::reader::list("/var/lib/myapp/reports")? {
//!     println!("{}", group.summary());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io;
use std::path::{Path, PathBuf};

use crate::report::Report;
use crate::writer;

/// One fingerprint's worth of history: every capture of a single bug.
#[derive(Debug, Clone)]
pub struct Group {
    /// The group directory, `<reports_dir>/<fingerprint>`.
    pub dir: PathBuf,
    /// The first capture, carrying the occurrence counters for the group.
    pub first: Report,
    /// The most recent capture, present once a bug has fired more than once.
    /// `None` for a one-off, where [`first`](Self::first) *is* the latest.
    pub latest: Option<Report>,
}

impl Group {
    /// The most recent capture — [`latest`](Self::latest) when the bug has
    /// repeated, otherwise the only one there is.
    #[must_use]
    pub fn most_recent(&self) -> &Report {
        self.latest.as_ref().unwrap_or(&self.first)
    }

    /// How many times this bug has been captured.
    #[must_use]
    pub fn occurrences(&self) -> u64 {
        self.first.occurrences
    }

    /// A one-line triage summary, e.g.
    /// `corruption ×412  4121763d  store.dangling_child  internal node references …`
    #[must_use]
    pub fn summary(&self) -> String {
        let r = &self.first;
        let site = r.domain_kind.as_deref().unwrap_or("-");
        format!(
            "{:<20} ×{:<6} {}  {}  {}",
            r.kind.slug(),
            r.occurrences,
            r.fingerprint,
            site,
            r.message
        )
    }
}

/// Load a single group directory.
pub fn load(dir: impl AsRef<Path>) -> io::Result<Group> {
    let dir = dir.as_ref();
    let first = writer::load_report(dir)?;
    // `latest.json` only exists once a group has repeated; a missing file is
    // the normal one-off case, not an error.
    let latest = match std::fs::read_to_string(dir.join("latest.json")) {
        Ok(text) => serde_json::from_str(&text).ok(),
        Err(_) => None,
    };
    Ok(Group {
        dir: dir.to_path_buf(),
        first,
        latest,
    })
}

/// Enumerate every report group under `reports_dir`, most recently seen first.
///
/// Unreadable or half-written group directories are skipped rather than failing
/// the listing: a triage tool must still show the other 63 bugs when one report
/// is being written concurrently. A missing `reports_dir` yields an empty list
/// — a project that has never crashed is the expected case, not an error.
pub fn list(reports_dir: impl AsRef<Path>) -> io::Result<Vec<Group>> {
    let entries = match std::fs::read_dir(reports_dir.as_ref()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut groups: Vec<Group> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| load(e.path()).ok())
        .collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.first.last_seen_ms));
    Ok(groups)
}

/// Total captures across every group — the honest "how bad is it" number, which
/// coalescing would otherwise hide behind a small directory count.
#[must_use]
pub fn total_occurrences(groups: &[Group]) -> u64 {
    groups.iter().map(Group::occurrences).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Env, EventKind, Meta, SCHEMA_VERSION};

    fn report(fp: &str, occurrences: u64, last_seen_ms: u128) -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            kind: EventKind::Corruption,
            message: "internal node references a non-btree page".to_owned(),
            meta: Meta {
                project: "myapp".to_owned(),
                version: "0.1.0".to_owned(),
                git_sha: None,
                build_id: None,
                captured_at_ms: last_seen_ms,
                pid: 1,
                ppid: None,
                thread: None,
            },
            error_chain: Vec::new(),
            backtrace: Vec::new(),
            breadcrumbs: Vec::new(),
            domain_kind: Some("store.dangling_child".to_owned()),
            domain: serde_json::Value::Null,
            env: Env::current(),
            artifacts: Vec::new(),
            fingerprint: fp.to_owned(),
            occurrences,
            first_seen_ms: 1,
            last_seen_ms,
        }
    }

    #[test]
    fn list_is_empty_when_nothing_has_ever_crashed() {
        let tmp = tempfile::tempdir().unwrap();
        let groups = list(tmp.path().join("never-created")).unwrap();
        assert!(groups.is_empty(), "a missing reports dir is not an error");
    }

    #[test]
    fn list_ranks_groups_by_most_recently_seen() {
        let tmp = tempfile::tempdir().unwrap();
        for (fp, last_seen) in [("aaaa", 100u128), ("bbbb", 300), ("cccc", 200)] {
            let dir = tmp.path().join(fp);
            std::fs::create_dir_all(&dir).unwrap();
            writer::write_report_json(&dir, &report(fp, 1, last_seen)).unwrap();
        }

        let groups = list(tmp.path()).unwrap();
        let order: Vec<&str> = groups
            .iter()
            .map(|g| g.first.fingerprint.as_str())
            .collect();
        assert_eq!(order, ["bbbb", "cccc", "aaaa"]);
    }

    #[test]
    fn a_repeated_group_exposes_both_first_and_latest() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ffff");
        std::fs::create_dir_all(&dir).unwrap();

        let mut first = report("ffff", 412, 900);
        first.meta.pid = 11;
        writer::write_report_json(&dir, &first).unwrap();
        let mut latest = report("ffff", 412, 900);
        latest.meta.pid = 99;
        writer::write_latest_json(&dir, &latest).unwrap();

        let group = load(&dir).unwrap();
        assert_eq!(group.occurrences(), 412);
        assert_eq!(group.first.meta.pid, 11);
        assert_eq!(group.most_recent().meta.pid, 99);
        assert!(group.summary().contains("×412"));
        assert!(group.summary().contains("store.dangling_child"));
    }

    #[test]
    fn a_one_off_group_reports_itself_as_the_most_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("eeee");
        std::fs::create_dir_all(&dir).unwrap();
        writer::write_report_json(&dir, &report("eeee", 1, 5)).unwrap();

        let group = load(&dir).unwrap();
        assert!(group.latest.is_none());
        assert_eq!(group.most_recent().meta.pid, group.first.meta.pid);
    }

    #[test]
    fn total_occurrences_sees_through_coalescing() {
        let tmp = tempfile::tempdir().unwrap();
        for (fp, n) in [("aaaa", 412u64), ("bbbb", 3)] {
            let dir = tmp.path().join(fp);
            std::fs::create_dir_all(&dir).unwrap();
            writer::write_report_json(&dir, &report(fp, n, 1)).unwrap();
        }
        let groups = list(tmp.path()).unwrap();
        assert_eq!(groups.len(), 2, "two directories...");
        assert_eq!(total_occurrences(&groups), 415, "...but 415 failures");
    }

    #[test]
    fn a_half_written_group_does_not_break_the_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let good = tmp.path().join("aaaa");
        std::fs::create_dir_all(&good).unwrap();
        writer::write_report_json(&good, &report("aaaa", 1, 1)).unwrap();
        // A directory being written right now: present, but no valid report.
        let partial = tmp.path().join("bbbb");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("report.json"), b"{ truncated").unwrap();

        let groups = list(tmp.path()).unwrap();
        assert_eq!(groups.len(), 1, "the readable group still lists");
    }
}

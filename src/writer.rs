// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persisting reports to disk and preserving the artifacts that travel with
//! them.
//!
//! A report is written as a self-contained directory
//! `<reports_dir>/<ts>-<fp8>/` holding `report.json` plus any preserved
//! artifacts (a minidump, a snapshot of a corrupt store). The directory name
//! embeds the short fingerprint so duplicates of one bug are obvious on sight.
//!
//! Writes are atomic-per-file (write to a temporary sibling, then rename) so a
//! crash mid-write never leaves a half-report that tooling would choke on.

use std::io;
use std::path::{Path, PathBuf};

use crate::report::{EventKind, Report};

/// Deterministic 64-bit FNV-1a. Stable across builds and platforms, so the same
/// failure fingerprints identically everywhere — unlike a `DefaultHasher`,
/// whose seed varies. Used only for grouping/dedup, never for security.
#[must_use]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Compute a stable grouping fingerprint from the identifying facets of a
/// failure: project, event kind, and the domain grouping key (falling back to a
/// normalized message when no domain context is present). Deliberately excludes
/// volatile data (page ids, timestamps, addresses) so instances of one bug
/// collapse to a single fingerprint.
#[must_use]
pub fn fingerprint(project: &str, kind: EventKind, domain_key: &str, message: &str) -> String {
    // Prefer the domain key; if absent, use a message with digits/hex stripped
    // so per-instance numbers don't split the group.
    let facet = if domain_key.is_empty() {
        normalize_message(message)
    } else {
        domain_key.to_owned()
    };
    let mut buf = String::with_capacity(project.len() + facet.len() + 16);
    buf.push_str(project);
    buf.push('\0');
    buf.push_str(kind.slug());
    buf.push('\0');
    buf.push_str(&facet);
    format!("{:016x}", fnv1a(buf.as_bytes()))
}

/// Collapse per-instance numerics in a message so `"page 828 failed"` and
/// `"page 832 failed"` group together.
fn normalize_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut prev_placeholder = false;
    for c in message.chars() {
        if c.is_ascii_hexdigit() {
            if !prev_placeholder {
                out.push('#');
                prev_placeholder = true;
            }
        } else {
            out.push(c);
            prev_placeholder = false;
        }
    }
    out
}

/// Compute and create the report directory for `report` under `reports_dir`.
/// The 8-char fingerprint prefix in the name makes repeats of one bug visible
/// without opening files; the timestamp prefix keeps the listing sortable.
///
/// Split from [`write_report_json`] so a caller can preserve artifacts into the
/// directory *before* the report's `artifacts` field is finalized and written.
pub fn report_dir_for(reports_dir: &Path, report: &Report) -> io::Result<PathBuf> {
    std::fs::create_dir_all(reports_dir)?;
    let fp8: String = report.fingerprint.chars().take(8).collect();
    let dir = reports_dir.join(format!("{}-{}", report.meta.captured_at_ms, fp8));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Atomically write `report.json` into an existing report `dir`.
pub fn write_report_json(dir: &Path, report: &Report) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&dir.join("report.json"), &json)
}

/// Convenience: create the report directory and write `report.json` in one
/// step (no artifacts). Returns the created directory.
pub fn write_report(reports_dir: &Path, report: &Report) -> io::Result<PathBuf> {
    let dir = report_dir_for(reports_dir, report)?;
    write_report_json(&dir, report)?;
    Ok(dir)
}

/// Copy a file or directory into an existing report directory as a named
/// artifact, returning the path relative to the report dir (for the report's
/// `Artifact::rel_path`). This is how a corrupt store is preserved beside its
/// report so offline `pagedb-fsck` runs against the exact bad state.
pub fn preserve_artifact(report_dir: &Path, src: &Path, name: &str) -> io::Result<String> {
    let dest = report_dir.join(name);
    if src.is_dir() {
        copy_dir_recursive(src, &dest)?;
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, &dest)?;
    }
    Ok(name.to_owned())
}

/// Find an already-preserved copy of artifact `name` in a *sibling* report
/// directory that shares this `fingerprint`, so a crash-loop re-detecting the
/// same failure doesn't re-copy the same multi-megabyte snapshot into every
/// report. Report dirs are named `<ts>-<fp8>`, so siblings of one bug share the
/// `-<fp8>` suffix; `exclude` (the current report's own dir) is skipped.
///
/// Returns the sibling copy's path *relative to `exclude`* (`../<sib>/<name>`),
/// suitable as an [`Artifact::rel_path`] that still resolves from the report
/// dir — the dedup is transparent to any tool that opens the report.
///
/// [`Artifact::rel_path`]: crate::report::Artifact::rel_path
#[must_use]
pub fn find_preserved_sibling(
    reports_dir: &Path,
    fingerprint: &str,
    name: &str,
    exclude: &Path,
) -> Option<PathBuf> {
    let fp8: String = fingerprint.chars().take(8).collect();
    let suffix = format!("-{fp8}");
    for entry in std::fs::read_dir(reports_dir).ok()?.flatten() {
        let dir = entry.path();
        if dir == exclude || !dir.is_dir() {
            continue;
        }
        if !entry.file_name().to_string_lossy().ends_with(&suffix) {
            continue;
        }
        if dir.join(name).exists() {
            return Some(PathBuf::from("..").join(entry.file_name()).join(name));
        }
    }
    None
}

/// Write `bytes` to `path` atomically: to a temp sibling then rename.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let to = dest.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ft.is_file() {
            std::fs::copy(entry.path(), &to)?;
        }
        // Symlinks/others are skipped: an artifact must be self-contained.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_ignores_volatile_numbers() {
        let a = fingerprint(
            "pagedb",
            EventKind::Corruption,
            "",
            "AEAD failed on page 828",
        );
        let b = fingerprint(
            "pagedb",
            EventKind::Corruption,
            "",
            "AEAD failed on page 832",
        );
        assert_eq!(a, b, "per-instance page ids must not split the group");
        assert_eq!(a.len(), 16);

        // Domain key takes precedence and groups independently of the message.
        let k1 = fingerprint("pagedb", EventKind::Corruption, "kind=0x09", "anything");
        let k2 = fingerprint(
            "pagedb",
            EventKind::Corruption,
            "kind=0x09",
            "different msg",
        );
        assert_eq!(k1, k2);
        let k3 = fingerprint("pagedb", EventKind::Corruption, "kind=0x02", "anything");
        assert_ne!(k1, k3, "different failure classes fingerprint differently");
    }

    #[test]
    fn fnv1a_matches_known_vector() {
        // Canonical FNV-1a/64 of "" is the offset basis.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn write_report_creates_named_dir_with_json() {
        let tmp = tempfile::tempdir().unwrap();
        let report = sample_report();
        let dir = write_report(tmp.path(), &report).unwrap();
        assert!(dir.join("report.json").is_file());
        let name = dir.file_name().unwrap().to_string_lossy();
        assert!(
            name.contains(&report.fingerprint[..8]),
            "fp prefix in dir name"
        );
        // Round-trips.
        let text = std::fs::read_to_string(dir.join("report.json")).unwrap();
        let back: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(back.fingerprint, report.fingerprint);
    }

    #[test]
    fn preserve_artifact_copies_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        // Fake "store" dir with a file.
        let store = tmp.path().join("store");
        std::fs::create_dir_all(store.join("seg")).unwrap();
        std::fs::write(store.join("main.db"), b"pages").unwrap();
        std::fs::write(store.join("seg/s0"), b"seg").unwrap();

        let report_dir = tmp.path().join("report");
        std::fs::create_dir_all(&report_dir).unwrap();
        let rel = preserve_artifact(&report_dir, &store, "store.corrupt").unwrap();
        assert_eq!(rel, "store.corrupt");
        assert!(report_dir.join("store.corrupt/main.db").is_file());
        assert!(report_dir.join("store.corrupt/seg/s0").is_file());
    }

    #[test]
    fn find_preserved_sibling_locates_prior_copy_and_skips_self() {
        let tmp = tempfile::tempdir().unwrap();
        let reports = tmp.path();
        // An earlier report of fingerprint `abcdef01…` that already preserved
        // `store.corrupt`.
        let prior = reports.join("100-abcdef01");
        std::fs::create_dir_all(prior.join("store.corrupt")).unwrap();
        std::fs::write(prior.join("store.corrupt/main.db"), b"pages").unwrap();
        // The current report dir (empty) — same fingerprint, later timestamp.
        let current = reports.join("200-abcdef01");
        std::fs::create_dir_all(&current).unwrap();

        let rel = find_preserved_sibling(reports, "abcdef0123456789", "store.corrupt", &current)
            .expect("prior sibling copy should be found");
        assert_eq!(rel, PathBuf::from("../100-abcdef01/store.corrupt"));
        // Resolves back to the real file from the current report dir.
        assert!(current.join(&rel).join("main.db").is_file());

        // A different fingerprint has no sibling to dedup against.
        assert!(
            find_preserved_sibling(reports, "ffffffffffffffff", "store.corrupt", &current)
                .is_none()
        );
    }

    fn sample_report() -> Report {
        use crate::report::{Env, Meta};
        Report {
            schema_version: crate::report::SCHEMA_VERSION,
            kind: EventKind::Corruption,
            message: "m".to_owned(),
            meta: Meta {
                project: "pagedb".to_owned(),
                version: "0.1.0".to_owned(),
                git_sha: None,
                build_id: None,
                captured_at_ms: 123,
                pid: 1,
            },
            error_chain: Vec::new(),
            backtrace: Vec::new(),
            breadcrumbs: Vec::new(),
            domain_kind: None,
            domain: serde_json::Value::Null,
            env: Env::current(),
            artifacts: Vec::new(),
            fingerprint: "abcdef0123456789".to_owned(),
        }
    }
}

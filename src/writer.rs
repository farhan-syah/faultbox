// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persisting reports to disk and preserving the artifacts that travel with
//! them.
//!
//! ## One directory per *bug*, not per *occurrence*
//!
//! A report lives in `<reports_dir>/<fingerprint>/`, holding `report.json`
//! (the first capture, plus occurrence counters), `latest.json` (the most
//! recent capture, once there is more than one), and any preserved artifacts.
//!
//! The directory is keyed by fingerprint alone. A crash loop re-detecting one
//! bug therefore *coalesces*: it increments [`Report::occurrences`] and
//! refreshes `latest.json` in place instead of writing a new directory per hit.
//! This is not a nicety — under a restart loop a per-occurrence layout writes
//! thousands of directories for a single bug, each with its own copy of any
//! preserved artifact. Keying on the fingerprint also makes lookup O(1) and
//! removes the timestamp-collision and cross-directory artifact-aliasing
//! problems that a per-occurrence layout has.
//!
//! ## Durability
//!
//! Writes are atomic *and* durable: content goes to a temporary sibling, is
//! `fsync`ed, renamed over the target, and then the containing directory is
//! `fsync`ed. A recorder that loses its own report to the crash it was
//! recording is worse than no recorder.
//!
//! Concurrent writers (a supervisor restarting a crashing daemon, or several
//! processes sharing a store) coordinate through a [`DirLock`] that is stolen
//! after [`LOCK_STALE_MS`] so a process dying mid-update cannot wedge the group
//! forever.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::report::{EventKind, Report};

/// How long a lock file may go untouched before a competing writer assumes its
/// holder died and steals it. Generous relative to the milliseconds an update
/// takes, tight enough that a crash loop is not stalled.
pub const LOCK_STALE_MS: u128 = 10_000;

/// Deterministic 64-bit FNV-1a. Stable across builds and platforms, so the same
/// failure fingerprints identically everywhere — unlike a `DefaultHasher`,
/// whose seed varies. Used only for grouping/dedup, never for security.
#[must_use]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash = fnv1a_step(hash, b);
    }
    hash
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv1a_step(hash: u64, b: u8) -> u64 {
    (hash ^ u64::from(b)).wrapping_mul(FNV_PRIME)
}

/// Compute a stable grouping fingerprint from the identifying facets of a
/// failure: project, event kind, and the domain grouping key (falling back to a
/// normalized message when no domain context is present). Deliberately excludes
/// volatile data (page ids, timestamps, addresses) so instances of one bug
/// collapse to a single fingerprint.
#[must_use]
pub fn fingerprint(project: &str, kind: EventKind, domain_key: &str, message: &str) -> String {
    // Prefer the domain key; if absent, use a message with per-instance numbers
    // stripped so they don't split the group.
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
///
/// Only *runs of digits* and `0x`-prefixed hex literals are replaced. Testing
/// each character with `is_ascii_hexdigit` would also match the letters `a-f`,
/// which shreds ordinary prose — `"checksum mismatch in header"` and
/// `"checksum mismatch in reader"` would both collapse to `"#h#ksum mism#t#h in
/// h#r"`-style noise and two unrelated bugs would share a fingerprint. Word
/// characters are therefore left alone; the volatile parts of a message are
/// numbers, and numbers are what we erase.
fn normalize_message(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < bytes.len() {
        // `0x`-prefixed hex literal: consume the prefix and all hex digits.
        if bytes[i] == b'0'
            && i + 2 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
            && bytes[i + 2].is_ascii_hexdigit()
        {
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            out.push('#');
            continue;
        }
        if bytes[i].is_ascii_digit() {
            // A run of digits, plus any hex letters trailing it so bare hex
            // dumps like `828af0` collapse as one token rather than two.
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            out.push('#');
            continue;
        }
        // Not a number: copy the whole UTF-8 character through untouched.
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&message[start..i]);
    }
    out
}

/// The directory holding every capture of one fingerprint.
#[must_use]
pub fn group_dir(reports_dir: &Path, fingerprint: &str) -> PathBuf {
    reports_dir.join(fingerprint)
}

/// Create the report directory for `fingerprint`, without locking it.
///
/// Split from [`lock_group`] so the expensive part of a capture — digesting and
/// copying a preserved artifact — can happen *outside* the lock. Holding the
/// lock across a multi-gigabyte copy would routinely exceed [`LOCK_STALE_MS`],
/// at which point a competing process steals the lock and writes the same
/// destination concurrently.
pub fn ensure_group_dir(reports_dir: &Path, fingerprint: &str) -> io::Result<PathBuf> {
    std::fs::create_dir_all(reports_dir)?;
    let dir = group_dir(reports_dir, fingerprint);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Take the group's lock. Hold it only for the short read-modify-write of the
/// group's metadata, never across bulk IO.
pub fn lock_group(dir: &Path) -> io::Result<DirLock> {
    DirLock::acquire(dir)
}

/// Create (or open) the report directory for `fingerprint` and take its lock.
///
/// Convenience for callers doing a short, artifact-free update. Anything that
/// copies bulk data should use [`ensure_group_dir`] + [`lock_group`] so the copy
/// happens outside the critical section.
pub fn open_group(reports_dir: &Path, fingerprint: &str) -> io::Result<(PathBuf, DirLock)> {
    let dir = ensure_group_dir(reports_dir, fingerprint)?;
    let lock = lock_group(&dir)?;
    Ok((dir, lock))
}

/// Read the canonical `report.json` from a group directory.
pub fn load_report(dir: &Path) -> io::Result<Report> {
    let text = std::fs::read_to_string(dir.join("report.json"))?;
    serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Atomically and durably write `report.json` into an existing report `dir`.
pub fn write_report_json(dir: &Path, report: &Report) -> io::Result<()> {
    write_json(&dir.join("report.json"), report)
}

/// Atomically and durably write `latest.json` — the most recent capture of a
/// coalesced group. Only written once a group has more than one occurrence, so
/// a one-off failure stays a single file.
pub fn write_latest_json(dir: &Path, report: &Report) -> io::Result<()> {
    write_json(&dir.join("latest.json"), report)
}

fn write_json(path: &Path, report: &Report) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(path, &json)
}

/// Commit `report` into its already-open, already-locked group directory,
/// coalescing it with any previous occurrence of the same fingerprint.
///
/// On a first sighting this simply writes `report.json`. On a repeat it carries
/// the first capture's forensic detail forward in `report.json` — advancing
/// only `occurrences` / `last_seen_ms` / the artifact list — and records *this*
/// capture in full as `latest.json`. `report` is updated in place with the
/// resulting counters so the caller can report them.
///
/// The caller must hold the group's [`DirLock`] for the duration.
pub fn commit_into(dir: &Path, report: &mut Report) -> io::Result<()> {
    match load_report(dir) {
        Ok(mut canonical) => {
            canonical.occurrences = canonical.occurrences.saturating_add(1);
            canonical.last_seen_ms = report.last_seen_ms;
            canonical.artifacts = report.artifacts.clone();
            report.occurrences = canonical.occurrences;
            report.first_seen_ms = canonical.first_seen_ms;
            write_report_json(dir, &canonical)?;
            write_latest_json(dir, report)
        }
        // First sighting — or an unreadable canonical file, which we replace
        // outright: a stale report must never block a live one.
        Err(_) => write_report_json(dir, report),
    }
}

/// Outcome of preserving an artifact beside its report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preserved {
    /// Bytes were copied in under the returned relative path.
    Copied {
        rel: String,
        bytes: u64,
        digest: String,
    },
    /// An identical copy (same digest) was already present from an earlier
    /// occurrence of this same bug, so nothing was re-copied.
    Reused {
        rel: String,
        bytes: u64,
        digest: String,
    },
    /// The source exceeded the configured size cap and was left in place.
    /// Recorded on the report so the omission is visible rather than silent.
    TooLarge { bytes: u64, limit: u64 },
}

/// An artifact copied to a staging path, awaiting the cheap rename into place.
#[derive(Debug, Clone)]
pub enum Staged {
    /// Bytes were copied to `tmp` and are ready to be moved to `name`.
    Ready {
        name: String,
        tmp: PathBuf,
        bytes: u64,
        digest: String,
    },
    /// An identical copy was already present, so nothing was copied.
    Reused {
        name: String,
        bytes: u64,
        digest: String,
    },
    /// The source exceeded the size cap and was left in place.
    TooLarge { bytes: u64, limit: u64 },
}

/// Digest a source artifact and copy it to a staging path beside its final
/// destination — the slow half of preserving, deliberately done **without the
/// group lock held**.
///
/// Holding the lock across a multi-gigabyte copy would routinely exceed
/// [`LOCK_STALE_MS`], at which point a competing process assumes the holder
/// died, steals the lock, and writes the same destination concurrently.
/// Staging is per-process, so two processes preserving at once can never
/// interleave their bytes into one artifact.
///
/// If an artifact of the same name is already present from an earlier
/// occurrence *and its digest matches*, nothing is copied ([`Staged::Reused`]) —
/// this is what stops a crash loop from writing the same snapshot over and
/// over. A *differing* digest is never silently aliased: the new bytes replace
/// the old, because a report claiming to hold the state it saw must hold it.
///
/// `max_bytes` caps the copy so preserving a store cannot fill the disk of the
/// very daemon whose durability is in question.
pub fn stage_artifact(
    report_dir: &Path,
    src: &Path,
    name: &str,
    max_bytes: u64,
) -> io::Result<Staged> {
    let (bytes, digest) = digest_of(src)?;
    if bytes > max_bytes {
        return Ok(Staged::TooLarge {
            bytes,
            limit: max_bytes,
        });
    }

    let dest = report_dir.join(name);
    if dest.exists()
        && let Ok((existing_bytes, existing_digest)) = digest_of(&dest)
        && existing_digest == digest
    {
        return Ok(Staged::Reused {
            name: name.to_owned(),
            bytes: existing_bytes,
            digest,
        });
    }

    let tmp = report_dir.join(format!("{name}.incoming.{}", std::process::id()));
    remove_any(&tmp)?;
    if src.is_dir() {
        copy_dir_recursive(src, &tmp)?;
    } else {
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, &tmp)?;
    }
    Ok(Staged::Ready {
        name: name.to_owned(),
        tmp,
        bytes,
        digest,
    })
}

/// Move a [`Staged`] artifact into its final name — the fast half, safe to run
/// while holding the group lock.
pub fn commit_artifact(report_dir: &Path, staged: Staged) -> io::Result<Preserved> {
    match staged {
        Staged::Reused {
            name,
            bytes,
            digest,
        } => Ok(Preserved::Reused {
            rel: name,
            bytes,
            digest,
        }),
        Staged::TooLarge { bytes, limit } => Ok(Preserved::TooLarge { bytes, limit }),
        Staged::Ready {
            name,
            tmp,
            bytes,
            digest,
        } => {
            let dest = report_dir.join(&name);
            remove_any(&dest)?;
            std::fs::rename(&tmp, &dest)?;
            sync_dir(report_dir);
            Ok(Preserved::Copied {
                rel: name,
                bytes,
                digest,
            })
        }
    }
}

/// Remove a path whether it is a file or a directory; absent is success.
fn remove_any(path: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Preserve an artifact in one step: stage, then commit.
///
/// Convenience for callers that hold no lock. `Capture::emit` calls the two
/// halves separately so the copy stays outside the group's critical section.
pub fn preserve_artifact(
    report_dir: &Path,
    src: &Path,
    name: &str,
    max_bytes: u64,
) -> io::Result<Preserved> {
    let staged = stage_artifact(report_dir, src, name, max_bytes)?;
    commit_artifact(report_dir, staged)
}

/// Total size and content digest of a file or directory tree.
///
/// The digest folds each entry's *relative path* and *contents* into one FNV-1a
/// value, so it distinguishes both differing bytes and differing layout. Entry
/// paths are sorted first so the digest does not depend on readdir order.
pub fn digest_of(path: &Path) -> io::Result<(u64, String)> {
    let mut hash = FNV_OFFSET;
    let mut total = 0u64;
    if path.is_dir() {
        let mut entries = Vec::new();
        collect_files(path, path, &mut entries)?;
        entries.sort();
        for rel in entries {
            for b in rel.to_string_lossy().as_bytes() {
                hash = fnv1a_step(hash, *b);
            }
            hash = fnv1a_step(hash, 0);
            let (len, h) = digest_file(&path.join(&rel), hash)?;
            hash = h;
            total += len;
        }
    } else {
        let (len, h) = digest_file(path, hash)?;
        hash = h;
        total = len;
    }
    Ok((total, format!("{hash:016x}")))
}

fn digest_file(path: &Path, mut hash: u64) -> io::Result<(u64, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            hash = fnv1a_step(hash, b);
        }
        len += n as u64;
    }
    Ok((len, hash))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if ft.is_file() {
            // Symlinks/others are skipped: an artifact must be self-contained.
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

/// How much history the reports directory keeps.
///
/// A recorder that fills the disk of the process it is monitoring has done more
/// harm than the bug it was recording, so retention is enforced, not advisory.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    /// Maximum number of distinct fingerprint groups to keep. The
    /// least-recently-seen groups are removed first.
    pub max_groups: usize,
    /// Maximum total bytes across the whole reports directory. Enforced after
    /// `max_groups`, again dropping least-recently-seen groups first.
    pub max_total_bytes: u64,
}

impl Default for Retention {
    fn default() -> Self {
        // 64 distinct bugs is far more than a triage session ever looks at, and
        // 2 GiB bounds the worst case of a handful of preserved stores.
        Retention {
            max_groups: 64,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Enforce `retention` over `reports_dir`, deleting least-recently-seen groups
/// first. Best effort: an unreadable or busy group is skipped, never fatal.
///
/// `keep` (the group just written) is never pruned, so the report that
/// triggered the sweep always survives it.
pub fn prune(reports_dir: &Path, retention: Retention, keep: &Path) {
    let Ok(entries) = std::fs::read_dir(reports_dir) else {
        return;
    };

    // (last_seen_ms, size_bytes, path) for each group, newest last.
    let mut groups: Vec<(u128, u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() || dir == keep {
            continue;
        }
        let (last_seen, size) = load_report(&dir)
            .map(|r| (r.last_seen_ms, reported_size(&r)))
            .unwrap_or((0, 0));
        groups.push((last_seen, size, dir));
    }
    groups.sort_by_key(|(ts, _, _)| *ts);

    // `keep` counts against both budgets even though it is never removed.
    let kept_size = load_report(keep).map(|r| reported_size(&r)).unwrap_or(0);
    let mut count = groups.len() + 1;
    let mut total: u64 = kept_size + groups.iter().map(|(_, s, _)| *s).sum::<u64>();

    for (_, size, dir) in &groups {
        if count <= retention.max_groups && total <= retention.max_total_bytes {
            break;
        }
        if std::fs::remove_dir_all(dir).is_ok() {
            count -= 1;
            total = total.saturating_sub(*size);
        }
    }
}

/// A group's size, taken from the sizes already recorded on its report rather
/// than by walking the tree.
///
/// `prune` runs after every capture, and a recursive `stat` of every file in
/// every retained group would put an unbounded directory walk on the hot path
/// of a crash loop — the precise situation where the recorder must stay cheap.
/// Artifacts dominate a group's size and their byte counts are already known,
/// so this is exact where it matters; the JSON files it ignores are kilobytes
/// against a retention budget measured in gigabytes.
fn reported_size(report: &Report) -> u64 {
    report
        .artifacts
        .iter()
        .filter_map(|a| a.bytes)
        .fold(0u64, u64::saturating_add)
}

/// A cross-process advisory lock over one report group, held for the duration
/// of a read-modify-write and released on drop.
///
/// Implemented as an exclusively-created lock file. A holder that dies without
/// releasing it (exactly what a crash reporter must expect) would deadlock
/// every later writer, so a lock older than [`LOCK_STALE_MS`] is stolen.
#[derive(Debug)]
pub struct DirLock {
    path: PathBuf,
}

impl DirLock {
    fn acquire(dir: &Path) -> io::Result<DirLock> {
        let path = dir.join(".lock");
        // Wait for the holder, however long it takes. The ONLY reason to take
        // the lock away is staleness, which means the holder died.
        //
        // An earlier version gave up after a fixed number of retries and stole
        // the lock anyway, reasoning that a corrupt counter beat a lost report.
        // That was wrong twice over: it is not a fallback but a race, and a
        // contended Windows runner hit it routinely — six processes updating
        // one group lost two of a hundred and fifty occurrences, silently.
        //
        // The wait cannot deadlock, because a lock older than `LOCK_STALE_MS`
        // is always stolen: whoever holds it is either finished (releasing it)
        // or dead (letting it go stale), so this loop always makes progress.
        // The critical section is a small read-modify-write of two JSON files —
        // bulk artifact copying happens outside it — so a live holder is never
        // close to the staleness window.
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = write!(f, "{}", std::process::id());
                    return Ok(DirLock { path });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn lock_is_stale(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    modified
        .elapsed()
        .map(|age| age.as_millis() > LOCK_STALE_MS)
        .unwrap_or(false)
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write `bytes` to `path` atomically *and* durably: to a temp sibling, fsync,
/// rename, then fsync the containing directory so the rename itself is durable.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
    Ok(())
}

/// fsync a directory so a rename into it survives power loss. Best effort:
/// unsupported on some filesystems and platforms, and never worth failing a
/// report over.
fn sync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
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
    fn fingerprint_ignores_volatile_numbers_but_not_words() {
        let a = fingerprint(
            "myapp",
            EventKind::Corruption,
            "",
            "AEAD failed on page 828",
        );
        let b = fingerprint(
            "myapp",
            EventKind::Corruption,
            "",
            "AEAD failed on page 832",
        );
        assert_eq!(a, b, "per-instance page ids must not split the group");
        assert_eq!(a.len(), 16);

        // Regression: hex *letters* inside ordinary words must not be erased,
        // or unrelated failures collapse into one fingerprint.
        let header = fingerprint(
            "myapp",
            EventKind::Corruption,
            "",
            "checksum mismatch in header",
        );
        let reader = fingerprint(
            "myapp",
            EventKind::Corruption,
            "",
            "checksum mismatch in reader",
        );
        assert_ne!(header, reader, "distinct messages must not merge");
        assert_ne!(
            fingerprint("myapp", EventKind::Corruption, "", "deadbeef"),
            fingerprint("myapp", EventKind::Corruption, "", "cafebabe"),
        );
    }

    #[test]
    fn normalize_message_erases_only_numbers() {
        assert_eq!(normalize_message("page 828 failed"), "page # failed");
        assert_eq!(normalize_message("kind 0x09 at 0xdeadBEEF"), "kind # at #");
        assert_eq!(
            normalize_message("checksum mismatch in header"),
            "checksum mismatch in header"
        );
        // A bare hex dump collapses as a single token.
        assert_eq!(normalize_message("blob 828af0 bad"), "blob # bad");
        // Non-ASCII passes through intact.
        assert_eq!(normalize_message("página 42"), "página #");
    }

    #[test]
    fn fnv1a_matches_known_vector() {
        // Canonical FNV-1a/64 of "" is the offset basis.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn group_dir_is_keyed_by_fingerprint_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, _la) = open_group(tmp.path(), "abcdef0123456789").unwrap();
        drop(_la);
        let (b, _lb) = open_group(tmp.path(), "abcdef0123456789").unwrap();
        assert_eq!(a, b, "same fingerprint reuses one directory");
    }

    #[test]
    fn report_json_round_trips_through_the_group_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let report = sample_report();
        let (dir, _lock) = open_group(tmp.path(), &report.fingerprint).unwrap();
        write_report_json(&dir, &report).unwrap();
        let back = load_report(&dir).unwrap();
        assert_eq!(back.fingerprint, report.fingerprint);
        assert_eq!(back.occurrences, 1);
    }

    #[test]
    fn preserve_artifact_copies_a_directory_then_reuses_identical_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        std::fs::create_dir_all(store.join("seg")).unwrap();
        std::fs::write(store.join("main.db"), b"pages").unwrap();
        std::fs::write(store.join("seg/s0"), b"seg").unwrap();

        let report_dir = tmp.path().join("report");
        std::fs::create_dir_all(&report_dir).unwrap();

        let first = preserve_artifact(&report_dir, &store, "store.corrupt", u64::MAX).unwrap();
        let Preserved::Copied { rel, bytes, digest } = first else {
            panic!("first preserve should copy, got {first:?}");
        };
        assert_eq!(rel, "store.corrupt");
        assert_eq!(bytes, 8, "5 bytes of main.db + 3 of seg/s0");
        assert!(report_dir.join("store.corrupt/main.db").is_file());
        assert!(report_dir.join("store.corrupt/seg/s0").is_file());

        // Second occurrence of the same bug over identical bytes: no re-copy.
        let second = preserve_artifact(&report_dir, &store, "store.corrupt", u64::MAX).unwrap();
        assert_eq!(
            second,
            Preserved::Reused {
                rel: "store.corrupt".to_owned(),
                bytes: 8,
                digest,
            }
        );
    }

    #[test]
    fn preserve_artifact_replaces_a_differing_snapshot_instead_of_aliasing_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("main.db"), b"first-state").unwrap();

        let report_dir = tmp.path().join("report");
        std::fs::create_dir_all(&report_dir).unwrap();
        preserve_artifact(&report_dir, &store, "snap", u64::MAX).unwrap();

        // The store is corrupt in a *different* way the next time around. The
        // report must hold the state it actually saw, not the earlier one.
        std::fs::write(store.join("main.db"), b"second-state").unwrap();
        let again = preserve_artifact(&report_dir, &store, "snap", u64::MAX).unwrap();
        assert!(
            matches!(again, Preserved::Copied { .. }),
            "differing bytes must be re-copied, got {again:?}"
        );
        assert_eq!(
            std::fs::read(report_dir.join("snap/main.db")).unwrap(),
            b"second-state"
        );
    }

    #[test]
    fn preserve_artifact_refuses_to_exceed_the_size_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let big = tmp.path().join("big.db");
        std::fs::write(&big, vec![0u8; 4096]).unwrap();
        let report_dir = tmp.path().join("report");
        std::fs::create_dir_all(&report_dir).unwrap();

        let out = preserve_artifact(&report_dir, &big, "big.db", 1024).unwrap();
        assert_eq!(
            out,
            Preserved::TooLarge {
                bytes: 4096,
                limit: 1024
            }
        );
        assert!(
            !report_dir.join("big.db").exists(),
            "oversized artifact must not be copied at all"
        );
    }

    #[test]
    fn digest_distinguishes_content_and_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        let c = tmp.path().join("c");
        for d in [&a, &b, &c] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(a.join("f"), b"same").unwrap();
        std::fs::write(b.join("f"), b"same").unwrap();
        // Same bytes, different layout.
        std::fs::write(c.join("g"), b"same").unwrap();

        assert_eq!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
        assert_ne!(
            digest_of(&a).unwrap().1,
            digest_of(&c).unwrap().1,
            "layout is part of the identity"
        );
    }

    #[test]
    fn prune_drops_least_recently_seen_groups_and_never_the_current_one() {
        let tmp = tempfile::tempdir().unwrap();
        let reports = tmp.path();

        // Three groups, distinguishable by last_seen_ms.
        for (fp, last_seen) in [("aaaa", 100u128), ("bbbb", 200), ("cccc", 300)] {
            let dir = reports.join(fp);
            std::fs::create_dir_all(&dir).unwrap();
            let mut r = sample_report();
            r.fingerprint = fp.to_owned();
            r.last_seen_ms = last_seen;
            write_report_json(&dir, &r).unwrap();
        }
        let keep = reports.join("aaaa"); // the oldest, but it is the current one

        prune(
            reports,
            Retention {
                max_groups: 2,
                max_total_bytes: u64::MAX,
            },
            &keep,
        );

        assert!(keep.is_dir(), "the just-written group is never pruned");
        assert!(!reports.join("bbbb").is_dir(), "oldest prunable group goes");
        assert!(reports.join("cccc").is_dir(), "newest group survives");
    }

    #[test]
    fn staging_leaves_no_incoming_path_behind_and_lands_the_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("main.db"), b"pages").unwrap();
        let report_dir = tmp.path().join("report");
        std::fs::create_dir_all(&report_dir).unwrap();

        // The slow half copies to a per-process staging path...
        let staged = stage_artifact(&report_dir, &store, "snap", u64::MAX).unwrap();
        let Staged::Ready {
            tmp: ref staging, ..
        } = staged
        else {
            panic!("expected a staged copy, got {staged:?}");
        };
        assert!(staging.is_dir(), "bytes land in staging first");
        assert!(
            !report_dir.join("snap").exists(),
            "the final name must not appear until commit"
        );

        // ...and the fast half renames it into place under the lock.
        let out = commit_artifact(&report_dir, staged).unwrap();
        assert!(matches!(out, Preserved::Copied { .. }));
        assert_eq!(
            std::fs::read(report_dir.join("snap/main.db")).unwrap(),
            b"pages"
        );

        let leftovers: Vec<_> = std::fs::read_dir(&report_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".incoming."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging paths must not leak: {leftovers:?}"
        );
    }

    #[test]
    fn prune_enforces_the_byte_budget_from_recorded_artifact_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        let reports = tmp.path();

        // Three groups, each claiming a 1 KiB artifact, oldest first.
        for (fp, last_seen) in [("aaaa", 100u128), ("bbbb", 200), ("cccc", 300)] {
            let dir = reports.join(fp);
            std::fs::create_dir_all(&dir).unwrap();
            let mut r = sample_report();
            r.fingerprint = fp.to_owned();
            r.last_seen_ms = last_seen;
            r.artifacts = vec![crate::report::Artifact {
                kind: "store".to_owned(),
                rel_path: "snap".to_owned(),
                note: None,
                digest: Some("0".to_owned()),
                bytes: Some(1024),
            }];
            write_report_json(&dir, &r).unwrap();
        }
        let keep = reports.join("cccc");

        // Budget for two groups' worth of bytes; the oldest must go.
        prune(
            reports,
            Retention {
                max_groups: usize::MAX,
                max_total_bytes: 2048,
            },
            &keep,
        );

        assert!(!reports.join("aaaa").is_dir(), "oldest evicted for bytes");
        assert!(reports.join("bbbb").is_dir());
        assert!(keep.is_dir(), "the current group is never pruned");
    }

    #[test]
    fn dir_lock_is_exclusive_and_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let lock = DirLock::acquire(&dir).unwrap();
        assert!(dir.join(".lock").exists());
        drop(lock);
        assert!(!dir.join(".lock").exists(), "drop releases the lock");
    }

    #[test]
    fn dir_lock_steals_a_stale_lock_rather_than_deadlocking() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let lock_path = dir.join(".lock");
        std::fs::write(&lock_path, b"99999").unwrap();
        // Backdate it well past the staleness window — a holder that crashed.
        let stale = std::time::SystemTime::now()
            - std::time::Duration::from_millis(LOCK_STALE_MS as u64 * 2);
        // Opened for writing, not with `File::open`: Windows needs write access
        // to set file times and returns "Access is denied" on a read-only
        // handle, so the read-only form fails there while passing on unix.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(stale)
            .unwrap();

        // Must not hang: a dead holder cannot wedge the group forever.
        let lock = DirLock::acquire(&dir).unwrap();
        drop(lock);
    }

    fn sample_report() -> Report {
        use crate::report::{Env, Meta};
        Report {
            schema_version: crate::report::SCHEMA_VERSION,
            kind: EventKind::Corruption,
            message: "m".to_owned(),
            meta: Meta {
                project: "myapp".to_owned(),
                version: "0.1.0".to_owned(),
                git_sha: None,
                build_id: None,
                captured_at_ms: 123,
                pid: 1,
                ppid: None,
                thread: None,
            },
            error_chain: Vec::new(),
            backtrace: Vec::new(),
            breadcrumbs: Vec::new(),
            domain_kind: None,
            domain: serde_json::Value::Null,
            env: Env::current(),
            artifacts: Vec::new(),
            fingerprint: "abcdef0123456789".to_owned(),
            occurrences: 1,
            first_seen_ms: 123,
            last_seen_ms: 123,
        }
    }
}

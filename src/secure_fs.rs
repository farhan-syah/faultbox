// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating report files and directories that only their owner can read, and
//! refusing artifact names that could escape the report directory.
//!
//! ## Why a report is owner-only
//!
//! A report is a *forensic* artifact. Redaction removes user content from the
//! strings, but the things travelling beside them are not redactable and were
//! never meant to be: a preserved artifact is a verbatim copy of the adopter's
//! store, and a minidump is the crashed process's entire address space —
//! encryption keys, session tokens, and whatever the user was working on, all
//! of it live in memory at the moment of the fault.
//!
//! Left at the process umask, those land at `0644` inside a `0755` directory,
//! which on any multi-user host means every local account can read them. So the
//! recorder creates its own directories at `0700` and its own files at `0600`,
//! and never widens either.
//!
//! ## Why temporary files are created exclusively
//!
//! Every durable write goes through a temporary sibling. `File::create` on a
//! predictable name follows a symlink planted there first, so an attacker who
//! can write to the reports directory could redirect the recorder's own write —
//! running as the reporting process — into a file of their choosing.
//!
//! `create_new(true)` is `O_CREAT | O_EXCL`, which POSIX requires to fail on a
//! symlink, so the plant is refused rather than followed. The names are also
//! unpredictable, so squatting them to deny service is guesswork rather than
//! arithmetic.
//!
//! ## Platform coverage
//!
//! The mode bits are a unix mechanism, and that is where this is enforced. On
//! Windows a created file or directory takes the inherited ACL of its parent,
//! and this crate does not set an explicit DACL — so on Windows the reports
//! directory is exactly as private as the location the adopter chose for it.
//! Under a user profile (`%LOCALAPPDATA%`) that is already per-user; somewhere
//! world-writable it is not, and no code here changes that.
//!
//! Exclusive creation, and therefore the symlink-plant refusal, applies on every
//! platform.

use std::io;
use std::path::{Path, PathBuf};

/// Mode for a directory the recorder creates: owner-only.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
/// Mode for a file the recorder creates: owner read/write.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Create `path` and any missing parents, owner-only.
///
/// An already-existing directory is left as it is — the reports directory is
/// the adopter's to configure, and silently rewriting the permissions of a path
/// they chose would be a surprise. [`harden_dir`] tightens the directories the
/// recorder itself owns.
pub(crate) fn create_dir_all_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Narrow an existing directory to owner-only.
///
/// Applied to report *group* directories, which belong entirely to the recorder
/// — including ones a previous version created at the umask default, whose
/// contents would otherwise stay world-readable forever. Best effort: a
/// filesystem without unix modes simply has nothing to do.
pub(crate) fn harden_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let mode = meta.permissions().mode();
        if mode & 0o7777 & !DIR_MODE != 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(DIR_MODE));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Create `path` for writing, owner-only, failing if it already exists.
///
/// Exclusive creation is what makes this safe against a pre-planted symlink;
/// callers use it for temporary siblings whose names they own.
pub(crate) fn create_new_private(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    options.open(path)
}

/// Narrow an existing file to owner-only. Used for files created by something
/// other than [`create_new_private`] — a minidump the IPC server opened, or a
/// report written by an earlier version of this crate.
pub(crate) fn harden_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if meta.permissions().mode() & 0o7777 & !FILE_MODE != 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(FILE_MODE));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The infix marking a path as one of the recorder's own temporaries.
///
/// Reserved, and enforced by [`validate_artifact_name`]: abandoned temporaries
/// are collected by a later capture, which recognises them by this substring. If
/// an artifact could carry it, a preserved snapshot named `db.tmp.1` would be
/// swept away as wreckage. Distinctive enough that nothing incidental matches.
pub const TEMP_INFIX: &str = ".faultbox-";

/// A process-local counter making temporary names unique within this process,
/// so two concurrent captures in one process cannot pick the same path.
static TEMP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Create a temporary file beside `final_path`, named `<final>.<tag>.<unique>`.
///
/// Returns the open handle and the path, so the caller can write, sync, and
/// rename. The name embeds process id, a monotonic counter and a clock reading;
/// exclusive creation retries on the (vanishingly unlikely, or adversarial)
/// collision, so a squatter can delay a write but never redirect one.
pub(crate) fn create_temp_beside(
    final_path: &Path,
    tag: &str,
) -> io::Result<(std::fs::File, PathBuf)> {
    let mut last = None;
    for _ in 0..64 {
        let path = temp_path(final_path, tag);
        match create_new_private(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find a free temporary name",
        )
    }))
}

/// A unique sibling path for `final_path`. Split out so the directory-copy path,
/// which needs a *directory* rather than a file, can share the naming.
pub(crate) fn temp_path(final_path: &Path, tag: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = final_path.file_name().map_or_else(
        || std::ffi::OsString::from("faultbox"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(
        "{TEMP_INFIX}{tag}.{}.{sequence}.{}",
        std::process::id(),
        crate::now_ms()
    ));
    match final_path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// Create a temporary *directory* beside `final_path`, owner-only and
/// exclusively — the recursive-copy counterpart to [`create_temp_beside`].
pub(crate) fn create_temp_dir_beside(final_path: &Path, tag: &str) -> io::Result<PathBuf> {
    let mut last = None;
    for _ in 0..64 {
        let path = temp_path(final_path, tag);
        match create_dir_exclusive(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find a free temporary name",
        )
    }))
}

/// Create exactly `path` as an owner-only directory, failing if it exists.
pub(crate) fn create_dir_exclusive(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(false)
            .mode(DIR_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().recursive(false).create(path)
    }
}

/// Names the recorder keeps for its own state inside a report directory. An
/// artifact may not take one of them, or preserving would overwrite the report
/// it is attached to — or the lock protecting it.
const RESERVED_NAMES: &[&str] = &[".lock", "report.json", "latest.json", "minidump"];

/// Validate an artifact name supplied by the adopter.
///
/// The name is joined onto the report directory, so an unchecked one is a path
/// traversal: `preserve(.., "../../escaped.db", ..)` writes outside the reports
/// directory entirely, and because committing an artifact removes whatever sits
/// at the destination first, it *deletes* outside it too — a whole directory
/// tree, in the case of a preserved store.
///
/// Names in real use are plain file names (`store.corrupt`, `snap.db`), so the
/// rule is simply that: one path component of ordinary file-name characters. It
/// also rules out absolute paths, Windows drive prefixes and alternate data
/// streams, embedded NULs, and the reserved names above.
pub fn validate_artifact_name(name: &str) -> io::Result<()> {
    let reject = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid artifact name {name:?}: {why}"),
        ))
    };

    if name.is_empty() {
        return reject("empty");
    }
    if name.len() > 255 {
        return reject("longer than 255 bytes");
    }
    if name == "." || name == ".." {
        return reject("a path traversal component");
    }
    if name.starts_with('.') {
        return reject("names beginning with a dot are reserved");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return reject("must be a single path component of ASCII letters, digits, '.', '_' or '-'");
    }
    if RESERVED_NAMES.iter().any(|r| name.eq_ignore_ascii_case(r)) {
        return reject("reserved for the recorder's own files");
    }
    if name.contains(TEMP_INFIX) {
        return reject("reserved: it marks the recorder's own temporary files");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_and_absolute_names_are_refused() {
        for name in [
            "../escape",
            "../../escape",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "C:\\windows",
            "stream:ads",
            ".",
            "..",
            "",
            ".hidden",
        ] {
            assert!(
                validate_artifact_name(name).is_err(),
                "{name:?} must be refused"
            );
        }
    }

    #[test]
    fn the_recorders_own_files_cannot_be_claimed() {
        for name in [".lock", "report.json", "latest.json", "REPORT.JSON"] {
            assert!(
                validate_artifact_name(name).is_err(),
                "{name:?} must be refused"
            );
        }
    }

    #[test]
    fn a_nul_byte_cannot_hide_inside_a_name() {
        assert!(validate_artifact_name("snap\0.db").is_err());
    }

    #[test]
    fn ordinary_artifact_names_are_accepted() {
        for name in [
            "snap",
            "store.corrupt",
            "main.db",
            "seg-0_1.bin",
            // Looks temporary, is not reserved, and must keep working.
            "db.tmp.1",
            "restore.incoming.2",
        ] {
            assert!(
                validate_artifact_name(name).is_ok(),
                "{name:?} must be accepted"
            );
        }
    }

    /// An artifact carrying the temporary marker would be collected as
    /// wreckage by a later capture's sweep, so it cannot be allowed to.
    #[test]
    fn an_artifact_cannot_carry_the_temporary_marker() {
        assert!(validate_artifact_name("snap.faultbox-incoming.1").is_err());
        assert!(
            temp_path(Path::new("/r/snap.db"), "incoming")
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(TEMP_INFIX),
            "the sweep and the namer must agree on the marker"
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_directories_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested/group");
        create_dir_all_private(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o700
        );

        let (file, path) = create_temp_beside(&dir.join("report.json"), "tmp").unwrap();
        drop(file);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_refused_rather_than_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"original").unwrap();

        let planted = tmp.path().join("planted");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let err = create_new_private(&planted).expect_err("must refuse a symlink");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"original",
            "the target must not have been written through"
        );
    }

    #[cfg(unix)]
    #[test]
    fn harden_dir_narrows_a_world_readable_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("legacy");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        harden_dir(&dir);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn temporary_names_do_not_repeat() {
        let base = Path::new("/tmp/reports/report.json");
        let a = temp_path(base, "tmp");
        let b = temp_path(base, "tmp");
        assert_ne!(a, b, "two temporaries must never collide");
        assert_eq!(a.parent(), base.parent(), "staged beside the destination");
    }
}

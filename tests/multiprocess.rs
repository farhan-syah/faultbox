// SPDX-License-Identifier: MIT OR Apache-2.0

//! Multi-process behaviour, driven through the `crash_helper` binary.
//!
//! Everything here needs genuinely separate processes: the crash monitor is a
//! re-exec of the host binary, the group lock is a cross-process file lock, and
//! the shared ring exists precisely so one process can read another's trail.
//! In-process tests can only ever approximate these, and the approximations are
//! exactly where the bugs hid.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the helper binary, provided by Cargo for `[[bin]]` targets.
fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_crash_helper")
}

/// Count live descendants of `pid`, transitively — used to prove that a
/// misconfigured monitor did not multiply.
///
/// procfs-only. Off Linux this returns `None` rather than `0`, so the caller
/// skips the assertion instead of passing it vacuously: "no /proc to read" and
/// "no children were spawned" must not look alike.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn descendant_count(pid: u32) -> Option<usize> {
    Some(descendant_count_procfs(pid))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn descendant_count(_pid: u32) -> Option<usize> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descendant_count_procfs(pid: u32) -> usize {
    // Walk /proc once, building child lists, then count reachable pids.
    let mut pairs: Vec<(u32, u32)> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(this) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if let Some(ppid) = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
        {
            pairs.push((ppid, this));
        }
    }
    let mut frontier = vec![pid];
    let mut seen = 0;
    while let Some(parent) = frontier.pop() {
        for (p, c) in &pairs {
            if *p == parent {
                seen += 1;
                frontier.push(*c);
            }
        }
    }
    seen
}

/// Wait for `predicate` to hold, up to `timeout`. Returns whether it held.
fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    predicate()
}

/// Find the single report group directory under `reports_dir`, if there is one.
fn sole_group(reports_dir: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(reports_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    (dirs.len() == 1).then(|| dirs.pop().unwrap())
}

/// The fork bomb, reproduced and pinned.
///
/// A process spawned as the crash monitor whose `main` never called
/// `run_crash_monitor_if_env()` falls through into normal startup. When it then
/// arms the handler itself, it spawns another copy — and each generation
/// doubles. This once produced thousands of runaway processes.
///
/// The guard must refuse: exit immediately, and spawn nothing.
#[cfg(feature = "native-crash")]
#[test]
fn a_monitor_that_failed_to_divert_exits_instead_of_multiplying() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = tmp.path().join("reports");

    let child = Command::new(helper())
        .args(["guard", reports.to_str().unwrap()])
        // Marks this process as a spawned monitor...
        .env(faultbox::native::ENV_SOCKET, "faultbox-test-not-listening")
        // ...whose `main` forgot to divert. Exactly the misuse under test.
        .env("FAULTBOX_TEST_SKIP_DIVERT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helper");

    let pid = child.id();
    // If the guard is broken this process spawns copies of itself; sample while
    // it is still alive rather than after it exits.
    let peak = descendant_count(pid);

    let output = child.wait_with_output().expect("helper exits");

    assert_eq!(
        output.status.code(),
        Some(70),
        "the guard must exit(70); exit 1 means it fell through and ran as a \
         duplicate application instance. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if let Some(peak) = peak {
        assert_eq!(peak, 0, "the guard must spawn nothing at all");
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("run_crash_monitor_if_env"),
        "the diagnostic must name the missing call"
    );
}

/// The monitor lifecycle end to end: arm the handler, take a real SIGSEGV, and
/// require that an out-of-process minidump and its report actually land.
///
/// Nothing short of a real crash exercises this — the signal handler, the IPC
/// handshake, and the monitor writing the dump from outside a dying address
/// space are all only reachable from an actual fault.
#[cfg(feature = "native-crash")]
#[test]
fn a_real_segfault_produces_a_minidump_and_a_native_crash_report() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = tmp.path().join("reports");

    let status = Command::new(helper())
        .args(["crash", reports.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn helper");

    assert!(
        !status.success(),
        "the helper must die of the fault, not exit cleanly"
    );

    // The monitor writes after the crashed process is gone, so poll.
    let landed = wait_until(Duration::from_secs(20), || {
        sole_group(&reports).is_some_and(|dir| dir.join("report.json").is_file())
    });
    assert!(
        landed,
        "no native-crash report appeared under {}",
        reports.display()
    );

    let dir = sole_group(&reports).unwrap();
    assert!(
        wait_until(Duration::from_secs(10), || dir.join("minidump").is_file()),
        "the minidump must be preserved beside the report"
    );

    let group = faultbox::reader::load(&dir).expect("report loads");
    assert_eq!(group.first.kind, faultbox::EventKind::NativeCrash);
    assert_eq!(group.first.meta.project, "helper");

    let artifact = group
        .first
        .artifacts
        .iter()
        .find(|a| a.kind == "minidump")
        .expect("the report references its minidump");
    assert_eq!(artifact.rel_path, "minidump");

    // A minidump begins with the `MDMP` magic; anything else means we captured
    // a truncated or empty file and would have shipped a useless artifact.
    let bytes = std::fs::read(dir.join("minidump")).unwrap();
    assert!(
        bytes.len() > 4 && &bytes[..4] == b"MDMP",
        "expected a real minidump, got {} bytes starting {:?}",
        bytes.len(),
        &bytes[..bytes.len().min(4)]
    );
}

/// Several processes hitting the same bug at once must coalesce into one group
/// with an exact occurrence count.
///
/// This is what the group lock is for. The single-process tests never contend
/// it, so a lost update here would go unnoticed: each process does a
/// read-modify-write of the same `report.json`, and without mutual exclusion
/// the counter silently undercounts.
#[test]
fn concurrent_processes_hitting_one_bug_do_not_lose_occurrences() {
    let tmp = tempfile::tempdir().unwrap();
    let reports = tmp.path().join("reports");
    std::fs::create_dir_all(&reports).unwrap();

    const PROCS: usize = 6;
    const PER_PROC: usize = 25;

    let children: Vec<_> = (0..PROCS)
        .map(|_| {
            Command::new(helper())
                .args(["emit", reports.to_str().unwrap(), &PER_PROC.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn helper")
        })
        .collect();

    for child in children {
        let out = child.wait_with_output().expect("helper exits");
        assert!(
            out.status.success(),
            "helper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let groups = faultbox::reader::list(&reports).unwrap();
    assert_eq!(groups.len(), 1, "one bug is one group, across processes");
    assert_eq!(
        groups[0].occurrences(),
        (PROCS * PER_PROC) as u64,
        "every occurrence must be counted; a shortfall means the group lock \
         allowed a lost update"
    );
    assert!(
        !groups[0].dir.join(".lock").exists(),
        "no lock may be left behind"
    );
}

/// The shared ring's entire purpose: a process reading a trail written by
/// *other* processes it never shared memory with in-process.
#[cfg(feature = "shared-ring")]
#[test]
fn a_shared_ring_carries_breadcrumbs_written_by_other_processes() {
    use faultbox::shared_ring::SharedRing;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ring");

    const PROCS: usize = 4;
    const PER_PROC: usize = 200;

    // Create the ring first so every writer joins the same one.
    let reader = SharedRing::open(&path, 4096).expect("open ring");

    let children: Vec<_> = (0..PROCS)
        .map(|i| {
            Command::new(helper())
                .args([
                    "ring-write",
                    path.to_str().unwrap(),
                    &format!("p{i}"),
                    &PER_PROC.to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn helper")
        })
        .collect();

    let mut pids = Vec::new();
    for child in children {
        pids.push(child.id());
        let out = child.wait_with_output().expect("helper exits");
        assert!(
            out.status.success(),
            "helper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let crumbs = reader.snapshot();
    assert_eq!(
        crumbs.len(),
        PROCS * PER_PROC,
        "every record from every process must survive"
    );

    // Each record must be intact — never a mix of two processes' bytes.
    for c in &crumbs {
        let (tag, i) = c.message.split_once('-').expect("well-formed record");
        assert!(tag.starts_with('p'), "torn record: {:?}", c.message);
        assert!(i.parse::<usize>().unwrap() < PER_PROC);
        assert!(
            c.pid.is_some_and(|p| p != std::process::id()),
            "crumbs must be attributed to the writing process"
        );
    }

    // All four writers are represented, and each contributed its full share.
    for i in 0..PROCS {
        let tag = format!("p{i}");
        let n = crumbs
            .iter()
            .filter(|c| c.message.starts_with(&format!("{tag}-")))
            .count();
        assert_eq!(n, PER_PROC, "process {tag} lost records");
    }
}

/// A ring wider than its capacity, written by several processes at once, must
/// still yield only intact records — the eviction path is where a seqlock bug
/// would show as a torn read rather than a lost one.
#[cfg(feature = "shared-ring")]
#[test]
fn a_shared_ring_under_multi_process_overflow_never_yields_a_torn_record() {
    use faultbox::shared_ring::SharedRing;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ring");
    const CAPACITY: usize = 64;
    let reader = SharedRing::open(&path, CAPACITY).unwrap();

    let children: Vec<_> = (0..4)
        .map(|i| {
            Command::new(helper())
                .args([
                    "ring-write",
                    path.to_str().unwrap(),
                    &format!("q{i}"),
                    "500",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn helper")
        })
        .collect();

    // Read concurrently with the writers, so snapshots race real eviction.
    for _ in 0..50 {
        for c in reader.snapshot() {
            let (tag, i) = c.message.split_once('-').expect("well-formed record");
            assert!(tag.starts_with('q'), "torn record: {:?}", c.message);
            assert!(
                i.parse::<usize>().unwrap() < 500,
                "torn index in {:?}",
                c.message
            );
        }
    }

    for child in children {
        assert!(child.wait_with_output().unwrap().status.success());
    }

    let final_snapshot = reader.snapshot();
    assert!(
        final_snapshot.len() <= CAPACITY,
        "the ring must stay bounded, got {}",
        final_snapshot.len()
    );
}

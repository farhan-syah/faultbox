// SPDX-License-Identifier: MIT OR Apache-2.0

//! Out-of-process native-crash capture (SIGSEGV, SIGABRT, SIGBUS, SIGILL,
//! SIGFPE, and stack overflow) as a minidump.
//!
//! A native crash cannot be safely handled inside the crashing process: its
//! address space may be corrupt and almost nothing is async-signal-safe. The
//! industry-standard answer (Breakpad, Crashpad, Sentry) is **out-of-process**
//! capture, which this module implements with the Embark crash toolchain:
//!
//! - [`install`] (called from [`crate::init`] when the `native-crash` feature
//!   is on) spawns a **monitor** process — a re-exec of the host binary with
//!   [`ENV_SOCKET`] set — connects a [`minidumper::Client`] to it, and installs
//!   [`crash_handler`] signal hooks whose only job on a crash is to ask the
//!   monitor for a dump.
//! - [`run_crash_monitor_if_env`] MUST be called by the host at the very top of
//!   `main`. In the spawned monitor it detects [`ENV_SOCKET`], runs the
//!   [`minidumper::Server`] loop (which writes the crashed process's minidump
//!   from *outside* its address space), emits a [`EventKind::NativeCrash`]
//!   report beside the minidump, and exits — it never returns to the host's
//!   normal startup. In a normal process the env var is absent and it returns
//!   `false` immediately.
//!
//! Breadcrumbs and [`crate::DomainContext`] live in the crashed process's RAM
//! and cannot cross to the monitor — the minidump is the forensic payload for
//! native crashes; offline symbolication against the build-id recovers the
//! faulting frames. This is an inherent property of out-of-process capture, not
//! a limitation of the schema.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::report::{Artifact, Env, EventKind, Meta, Report, SCHEMA_VERSION};
use crate::writer;

/// Presence of this env var marks a process as the crash monitor and carries
/// the IPC socket name. Set by [`install`] on the spawned child.
pub const ENV_SOCKET: &str = "FAULTBOX_CRASH_SOCKET";
const ENV_REPORTS_DIR: &str = "FAULTBOX_CRASH_REPORTS_DIR";
const ENV_PROJECT: &str = "FAULTBOX_CRASH_PROJECT";
const ENV_VERSION: &str = "FAULTBOX_CRASH_VERSION";
const ENV_GIT_SHA: &str = "FAULTBOX_CRASH_GIT_SHA";
const ENV_BUILD_ID: &str = "FAULTBOX_CRASH_BUILD_ID";

/// Keeps the crash handler and IPC client alive for the process's lifetime.
/// Dropping either would uninstall the hooks, so they are parked here.
static GUARD: OnceLock<Guard> = OnceLock::new();

struct Guard {
    _handler: crash_handler::CrashHandler,
    // The client is owned by the crash-event closure inside the handler, so it
    // needs no separate storage; the handler keeps it alive.
}

// The handler and client are single-owner and only touched from the signal
// path; parking them in a OnceLock is sound.
unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}

/// If this process was spawned as the crash monitor (via [`ENV_SOCKET`]), run
/// the minidump server to completion and [`exit`](std::process::exit) — never
/// returning to the host's normal startup. Otherwise return `false` at once.
///
/// Call at the very top of `main`, before argument parsing or any other work.
#[must_use]
pub fn run_crash_monitor_if_env() -> bool {
    let Ok(socket) = std::env::var(ENV_SOCKET) else {
        return false;
    };
    // Clear the marker before doing anything else so that any process the
    // monitor itself spawns does not inherit monitor mode and mistake itself
    // for a failed-to-divert child.
    //
    // SAFETY: this runs at the very top of `main`, before the program has
    // started any threads, so there is no concurrent reader of the environment.
    unsafe { std::env::remove_var(ENV_SOCKET) };
    let code = run_monitor(&socket);
    std::process::exit(code);
}

/// Spawn the monitor, connect to it, and install native crash hooks. Best
/// effort: on any failure it logs to stderr and returns without installing, so
/// the base recorder keeps working. Idempotent — a second call is ignored.
pub fn install(cfg: &crate::Config) {
    if GUARD.get().is_some() {
        return;
    }

    // Reaching here with `ENV_SOCKET` set means this process *is* a spawned
    // monitor whose host never called `run_crash_monitor_if_env()` — so instead
    // of running the server loop it fell through into the application's normal
    // startup, and is now about to spawn a monitor of its own. Each generation
    // would double, and the host would be fork-bombed by its own crash
    // reporter.
    //
    // Refuse, and exit: a duplicate instance of the application is strictly
    // worse than a missing crash handler. For a daemon it means two processes
    // bound to the same port and writing the same store — this crate causing
    // exactly the corruption it exists to report on.
    if std::env::var_os(ENV_SOCKET).is_some() {
        eprintln!(
            "faultbox: FATAL — this process was spawned as the crash monitor, but \
             `faultbox::run_crash_monitor_if_env()` was never called, so it resumed \
             normal startup as a duplicate instance of the application.\n\
             faultbox: add this as the first statement in `main`:\n\
             faultbox:     if faultbox::run_crash_monitor_if_env() {{ return; }}\n\
             faultbox: exiting to avoid spawning further copies."
        );
        std::process::exit(70);
    }
    match try_install(cfg) {
        Ok(guard) => {
            let _ = GUARD.set(guard);
        }
        Err(e) => {
            eprintln!("faultbox: native-crash capture not installed: {e}");
        }
    }
}

fn try_install(cfg: &crate::Config) -> Result<Guard, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    // Unique per (pid, start) so concurrent processes don't collide. No RNG
    // dependency: pid + capture time is sufficiently unique for a socket name.
    let socket = format!(
        "faultbox-{}-{}-{}",
        cfg.project,
        std::process::id(),
        crate::now_ms()
    );

    // Spawn the monitor: a re-exec of ourselves that `run_crash_monitor_if_env`
    // will divert into the server loop. It inherits no args (empty argv) — the
    // env var alone selects monitor mode.
    let mut cmd = std::process::Command::new(&exe);
    cmd.env(ENV_SOCKET, &socket)
        .env(ENV_REPORTS_DIR, &cfg.reports_dir)
        .env(ENV_PROJECT, &cfg.project)
        .env(ENV_VERSION, &cfg.version)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(sha) = &cfg.git_sha {
        cmd.env(ENV_GIT_SHA, sha);
    }
    if let Some(bid) = &cfg.build_id {
        cmd.env(ENV_BUILD_ID, bid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Own process group so the monitor is not killed by signals delivered
        // to the app's group, and outlives a shell that backgrounded the app.
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn monitor: {e}"))?;

    // Connect to the monitor, retrying while it binds the socket.
    //
    // If this fails the child must be killed, not leaked. The monitor is a
    // re-exec of the host binary, and it only diverts into the server loop
    // because `run_crash_monitor_if_env` runs at the top of `main`. A host that
    // forgot that call — or a child that failed to bind — is instead a *second
    // full instance of the application*, which for a daemon means a second
    // process contending for the same ports and the same store. Leaving it
    // running would make this crate the cause of the corruption it exists to
    // report.
    let client = match connect_with_retry(&socket) {
        Ok(client) => client,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{e} — the monitor process was killed. Ensure `main` calls \
                 `faultbox::run_crash_monitor_if_env()` before any other work."
            ));
        }
    };

    // Install the crash handler. Its closure asks the monitor to dump on a
    // crash; the boolean tells crash-handler whether we handled it.
    // SAFETY: `make_crash_event` is unsafe because the closure runs in a signal
    // context; it only calls `request_dump` (async-signal-safe IPC in
    // minidumper) and returns — no allocation or unwinding.
    let handler = crash_handler::CrashHandler::attach(unsafe {
        crash_handler::make_crash_event(move |cc: &crash_handler::CrashContext| {
            let handled = client.request_dump(cc).is_ok();
            crash_handler::CrashEventResult::Handled(handled)
        })
    })
    .map_err(|e| format!("attach crash handler: {e}"))?;

    Ok(Guard { _handler: handler })
}

/// Connect a client to the monitor's socket, retrying briefly while the child
/// process binds it.
fn connect_with_retry(socket: &str) -> Result<minidumper::Client, String> {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let sock_path = std::env::temp_dir().join(socket);
    let mut last = String::new();
    for _ in 0..200 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let name = minidumper::SocketName::Abstract(socket);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let name = minidumper::SocketName::Path(&sock_path);
        match minidumper::Client::with_name(name) {
            Ok(c) => return Ok(c),
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    Err(format!("connect to monitor timed out: {last}"))
}

/// Monitor entry point: run the minidump server until the app disconnects.
/// Returns the process exit code.
fn run_monitor(socket: &str) -> i32 {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let sock_path = std::env::temp_dir().join(socket);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let name = minidumper::SocketName::Abstract(socket);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let name = minidumper::SocketName::Path(&sock_path);
    let mut server = match minidumper::Server::with_name(name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("faultbox monitor: bind {socket}: {e}");
            return 1;
        }
    };
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let handler = MonitorHandler::from_env();
    match server.run(Box::new(handler), &shutdown, None) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("faultbox monitor: server run: {e}");
            1
        }
    }
}

/// Server-side handler: writes each minidump to a fresh report directory and
/// drops a [`EventKind::NativeCrash`] `report.json` beside it.
struct MonitorHandler {
    reports_dir: PathBuf,
    project: String,
    version: String,
    git_sha: Option<String>,
    build_id: Option<String>,
}

impl MonitorHandler {
    fn from_env() -> Self {
        let opt = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        MonitorHandler {
            reports_dir: opt(ENV_REPORTS_DIR)
                .map_or_else(|| PathBuf::from("faultbox-crash-reports"), PathBuf::from),
            project: opt(ENV_PROJECT).unwrap_or_else(|| "unknown".to_owned()),
            version: opt(ENV_VERSION).unwrap_or_else(|| "0.0.0".to_owned()),
            git_sha: opt(ENV_GIT_SHA),
            build_id: opt(ENV_BUILD_ID),
        }
    }

    /// The message and fingerprint every native crash of this build shares.
    ///
    /// Finer grouping by faulting frame is deliberately an offline step against
    /// the minidump + build-id: the monitor cannot symbolicate, and guessing
    /// here would scatter one bug across many groups.
    fn crash_fingerprint(&self) -> (&'static str, String) {
        let message = "native crash captured out-of-process (see minidump)";
        (
            message,
            writer::fingerprint(&self.project, EventKind::NativeCrash, "", message),
        )
    }

    /// Build a native-crash report referencing `minidump` (already inside
    /// `report_dir`, named `minidump`) and commit it into the group.
    fn write_report(&self, report_dir: &std::path::Path) {
        let (message, fingerprint) = self.crash_fingerprint();
        let now = crate::now_ms();
        let (bytes, digest) = writer::digest_of(&report_dir.join("minidump"))
            .map_or((None, None), |(b, d)| (Some(b), Some(d)));
        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            kind: EventKind::NativeCrash,
            message: message.to_owned(),
            meta: Meta {
                project: self.project.clone(),
                version: self.version.clone(),
                git_sha: self.git_sha.clone(),
                build_id: self.build_id.clone(),
                captured_at_ms: now,
                pid: std::process::id(),
                ppid: Meta::current_ppid(),
                thread: None,
            },
            error_chain: Vec::new(),
            backtrace: Vec::new(),
            breadcrumbs: Vec::new(),
            domain_kind: None,
            domain: serde_json::Value::Null,
            env: Env::current(),
            artifacts: vec![Artifact {
                kind: "minidump".to_owned(),
                rel_path: "minidump".to_owned(),
                note: Some(
                    "inspect with `minidump-stackwalk minidump` against the \
                     build-id's symbols"
                        .to_owned(),
                ),
                digest,
                bytes,
            }],
            fingerprint,
            occurrences: 1,
            first_seen_ms: now,
            last_seen_ms: now,
        };
        let _ = writer::commit_into(report_dir, &mut report);
    }
}

impl minidumper::ServerHandler for MonitorHandler {
    fn create_minidump_file(&self) -> Result<(std::fs::File, PathBuf), std::io::Error> {
        // Pre-create the group directory so the minidump lands directly inside
        // it as `minidump`; the report.json is written in `on_minidump_created`.
        // The group is keyed by fingerprint, so a crash loop overwrites one
        // minidump and bumps a counter rather than filling the disk.
        let (_, fingerprint) = self.crash_fingerprint();
        let dir = writer::group_dir(&self.reports_dir, &fingerprint);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("minidump");
        let file = std::fs::File::create(&path)?;
        Ok((file, path))
    }

    fn on_minidump_created(
        &self,
        result: Result<minidumper::MinidumpBinary, minidumper::Error>,
    ) -> minidumper::LoopAction {
        match result {
            Ok(bin) => {
                // `bin.path` is `<report_dir>/minidump`; its parent is the dir.
                if let Some(report_dir) = bin.path.parent() {
                    self.write_report(report_dir);
                }
            }
            Err(e) => eprintln!("faultbox monitor: minidump write failed: {e}"),
        }
        // One crash per client is all we can capture; keep serving in case
        // another client (there is only one) reconnects — disconnect exits.
        minidumper::LoopAction::Continue
    }

    fn on_message(&self, _kind: u32, _buffer: Vec<u8>) {}

    fn on_client_disconnected(&self, num_clients: usize) -> minidumper::LoopAction {
        // The monitored app is gone; nothing left to guard.
        if num_clients == 0 {
            minidumper::LoopAction::Exit
        } else {
            minidumper::LoopAction::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_writes_native_crash_report_beside_minidump() {
        let tmp = tempfile::tempdir().unwrap();
        let handler = MonitorHandler {
            reports_dir: tmp.path().to_path_buf(),
            project: "myapp".to_owned(),
            version: "0.1.0".to_owned(),
            git_sha: None,
            build_id: Some("deadbeef".to_owned()),
        };
        // Simulate what the server does: a report dir with the minidump already
        // written into it as `minidump`.
        let report_dir = tmp.path().join("100-abcd1234");
        std::fs::create_dir_all(&report_dir).unwrap();
        std::fs::write(report_dir.join("minidump"), b"MDMP\0\0\0\0").unwrap();

        handler.write_report(&report_dir);

        let text = std::fs::read_to_string(report_dir.join("report.json")).unwrap();
        let report: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(report.kind, EventKind::NativeCrash);
        assert_eq!(report.meta.project, "myapp");
        assert_eq!(report.meta.build_id.as_deref(), Some("deadbeef"));
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.artifacts[0].kind, "minidump");
        assert_eq!(report.artifacts[0].rel_path, "minidump");
    }

    #[test]
    fn native_crash_reports_share_a_fingerprint_per_build() {
        // All native crashes for one project group together live (finer
        // grouping is an offline step against the minidump).
        let a = writer::fingerprint("myapp", EventKind::NativeCrash, "", "native crash captured");
        let b = writer::fingerprint("myapp", EventKind::NativeCrash, "", "native crash captured");
        assert_eq!(a, b);
        let other = writer::fingerprint(
            "otherapp",
            EventKind::NativeCrash,
            "",
            "native crash captured",
        );
        assert_ne!(a, other, "different projects fingerprint apart");
    }
}

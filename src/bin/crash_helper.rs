// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test helper: a real binary with a real `main`, used by the multi-process
//! integration tests.
//!
//! These scenarios cannot be tested from a `#[test]` alone. A test binary's
//! `main` belongs to the libtest harness, so it can never call
//! [`faultbox::run_crash_monitor_if_env`] first — which means a spawned monitor
//! would always fall through into the harness and be treated as a
//! failed-to-divert child. Anything exercising the monitor lifecycle, or two
//! genuinely separate processes contending for a lock or a shared ring, needs a
//! binary whose `main` is ours.
//!
//! Excluded from the published package (see `exclude` in `Cargo.toml`); it
//! exists only for `tests/multiprocess.rs`.

use std::path::PathBuf;

fn main() {
    // FIRST, exactly as the documentation requires: a monitor process diverts
    // here and never reaches the code below.
    //
    // `FAULTBOX_TEST_SKIP_DIVERT` deliberately omits this, to reproduce the
    // misuse that the fork-bomb guard exists to catch.
    if std::env::var_os("FAULTBOX_TEST_SKIP_DIVERT").is_none()
        && faultbox::run_crash_monitor_if_env()
    {
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        // Arm the native-crash handler and then take a real SIGSEGV, so the
        // out-of-process monitor has to produce an actual minidump. An optional
        // third argument attaches a shared breadcrumb ring, whose trail the
        // monitor must recover from the dead process.
        "crash" => crash(PathBuf::from(&args[2]), args.get(3).map(PathBuf::from)),
        // Arm the handler in a process that skipped the divert call. The guard
        // must exit(70) instead of spawning another copy of this binary.
        "guard" => guard(PathBuf::from(&args[2])),
        // Append breadcrumbs to a shared ring from a separate process.
        "ring-write" => ring_write(&args[2], &args[3], args[4].parse().unwrap()),
        // Emit the same fingerprint repeatedly from a separate process, to
        // contend with a sibling on the group lock.
        "emit" => emit(PathBuf::from(&args[2]), args[3].parse().unwrap()),
        other => {
            eprintln!("crash_helper: unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}

fn config(reports_dir: PathBuf) -> faultbox::Config {
    faultbox::Config::new("helper", "0.1.0", reports_dir).install_panic_hook(false)
}

#[cfg(feature = "native-crash")]
fn crash(reports_dir: PathBuf, ring_path: Option<PathBuf>) -> ! {
    let mut cfg = config(reports_dir).install_native_crash_handler(true);

    #[cfg(feature = "shared-ring")]
    if let Some(path) = &ring_path {
        let ring = faultbox::shared_ring::SharedRing::open(path, 256).expect("open ring");
        cfg = cfg.shared_ring(std::sync::Arc::new(ring));
    }
    let _ = &ring_path;

    faultbox::init(cfg);

    // Operations leading up to the fault. These go to the shared ring, which
    // survives this process; the in-process recorder does not.
    faultbox::breadcrumb!(Info, "helper.open", "opened store");
    faultbox::breadcrumb!(Warn, "helper.verify", "checksum looked wrong");

    // Give the handler a moment to finish attaching before faulting.
    std::thread::sleep(std::time::Duration::from_millis(200));
    // SAFETY: intentionally dereferencing null to raise SIGSEGV. This is the
    // event under test.
    unsafe {
        std::ptr::null::<u8>().read_volatile();
    }
    unreachable!("the process must not survive a null dereference");
}

#[cfg(not(feature = "native-crash"))]
fn crash(_reports_dir: PathBuf, _ring_path: Option<PathBuf>) -> ! {
    std::process::exit(3);
}

fn guard(reports_dir: PathBuf) {
    // Reached only with FAULTBOX_CRASH_SOCKET set by the parent *and* the
    // divert call skipped: `init` must refuse and exit rather than spawn.
    faultbox::init(config(reports_dir).install_native_crash_handler(true));
    // If the guard did not fire we are a duplicate application instance, which
    // is the bug. Exit distinguishably so the test can tell the two apart.
    eprintln!("crash_helper: guard did not fire");
    std::process::exit(1);
}

#[cfg(feature = "shared-ring")]
fn ring_write(path: &str, tag: &str, count: usize) {
    let ring = faultbox::shared_ring::SharedRing::open(path, 4096).expect("open ring");
    for i in 0..count {
        ring.record(
            faultbox::breadcrumbs::Level::Info,
            "helper.write",
            &format!("{tag}-{i}"),
        );
    }
}

#[cfg(not(feature = "shared-ring"))]
fn ring_write(_path: &str, _tag: &str, _count: usize) {
    std::process::exit(3);
}

fn emit(reports_dir: PathBuf, count: usize) {
    faultbox::init(config(reports_dir));
    for i in 0..count {
        let ctx = faultbox::Adhoc {
            kind: "helper.contended",
            key: "class=1".to_owned(),
            value: serde_json::json!({ "i": i }),
        };
        let _ = faultbox::Capture::new(faultbox::EventKind::Corruption, "contended failure")
            .domain(&ctx)
            .emit();
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0

//! `faultbox` — a production black-box recorder.
//!
//! One report format for every failure class — Rust panics, native crashes,
//! detected data corruption, and invariant violations — each carrying a
//! **flight-recorder breadcrumb trail** of the operations that led up to it, a
//! **build-id** for offline symbolication (no debug symbols shipped to users),
//! and, for corruption, a **preserved snapshot** of the bad artifact. The goal:
//! debug a production failure *from its report*, without reproduction.
//!
//! Corruption and invariant violations are usually *returned errors*, not
//! crashes, so a panic-only crash reporter never sees them — capturing those,
//! with rich per-project [`DomainContext`], is the reason this crate exists.
//!
//! ## Shape
//!
//! - [`init`] once at startup: names the project, sizes the flight recorder,
//!   installs the panic hook, and sets the redactor + reports directory.
//! - Sprinkle [`breadcrumb!`] at significant operations (commits, allocs,
//!   frees, reopens). It is a no-op until `init` runs, so libraries may emit
//!   crumbs unconditionally.
//! - At a detection site, [`Capture`] a report with a [`DomainContext`] and,
//!   optionally, [`Capture::preserve`] the offending artifact.
//!
//! The crate is synchronous and `std`-only so it is safe to call from a panic
//! hook and usable by any project regardless of async runtime.

pub mod breadcrumbs;
pub mod build_id;
pub mod context;
pub mod digest;
#[cfg(feature = "native-crash")]
pub mod native;
pub mod panic;
pub mod reader;
pub mod redact;
pub mod report;
pub mod secure_fs;
#[cfg(feature = "shared-ring")]
pub mod shared_ring;
#[cfg(feature = "tracing")]
pub mod tracing_layer;
pub mod writer;

use std::path::PathBuf;
use std::sync::OnceLock;
// Unused on `wasm32-unknown-unknown`, which has no clock — see `now_ms`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use std::time::{SystemTime, UNIX_EPOCH};

pub use context::{Adhoc, DomainContext};
pub use redact::{BasicRedactor, NoopRedactor, Redactor};
pub use report::{Artifact, Env, EventKind, Frame, Meta, Report, SCHEMA_VERSION};
#[cfg(feature = "tracing")]
pub use tracing_layer::BreadcrumbLayer;
pub use writer::Retention;

/// Re-exported so adopters can build [`DomainContext::to_json`] payloads
/// (`faultbox::serde_json::json!{…}`) without taking their own dependency.
pub use serde_json;

/// Process-wide configuration, set once via [`init`].
pub struct Config {
    /// Adopting project name, e.g. `"myapp"`.
    pub project: String,
    /// Package semver.
    pub version: String,
    /// Git commit of the build, if known (typically `option_env!` from a build
    /// script). `None` is acceptable but weakens traceability.
    pub git_sha: Option<String>,
    /// GNU build-id; defaults to the running binary's via [`build_id::read_self`].
    pub build_id: Option<String>,
    /// Directory reports are written under, e.g. `~/.myapp/crash-reports`.
    pub reports_dir: PathBuf,
    /// Flight-recorder capacity (number of breadcrumbs retained).
    pub breadcrumb_capacity: usize,
    /// Compile-time feature flags worth recording on every report — the build's
    /// feature selection is often what separates a reproducible failure from an
    /// unreproducible one.
    pub features: Vec<String>,
    /// How much history the reports directory keeps. Enforced after every
    /// [`Capture::emit`] so a crash loop cannot fill the disk.
    pub retention: writer::Retention,
    /// Largest artifact [`Capture::preserve`] will copy. A larger source is
    /// left in place and the omission is noted on the report rather than
    /// silently filling the disk.
    pub preserve_max_bytes: u64,
    /// Redactor applied to every string entering a report. Defaults to a no-op;
    /// production adopters MUST supply a real one.
    pub redactor: Box<dyn Redactor>,
    /// An optional breadcrumb ring in shared memory, keyed to the artifact
    /// rather than this process (`shared-ring` feature).
    ///
    /// When set, crumbs are recorded to both the in-process recorder and this
    /// ring, and reports carry the two trails merged by timestamp — so a
    /// corruption detected here can show the writes that caused it *in another
    /// process*. Open one per store, e.g. at `<store>/.faultbox-ring`.
    #[cfg(feature = "shared-ring")]
    pub shared_ring: Option<std::sync::Arc<shared_ring::SharedRing>>,
    /// Whether [`init`] installs the panic hook.
    pub install_panic_hook: bool,
    /// Whether [`init`] installs the out-of-process native-crash handler
    /// (`native-crash` feature only).
    ///
    /// **Defaults to `false`, and must be opted into explicitly**, because
    /// arming it imposes a hard requirement on the host: `main` *must* call
    /// [`run_crash_monitor_if_env`] before doing anything else. The monitor is a
    /// re-exec of the host binary, so if that call is missing the spawned child
    /// does not become a monitor — it runs the application again from the top,
    /// calls `init` again, and spawns another child. That is an exponential
    /// fork bomb, and it is not hypothetical: it is what happens the first time
    /// anyone enables the feature and forgets the call.
    ///
    /// Enabling the `native-crash` Cargo feature therefore does *not* arm this
    /// on its own — a feature flag can be turned on transitively by a
    /// dependency, and no dependency can make the host's `main` cooperate.
    pub install_native_crash_handler: bool,
}

impl Config {
    /// A config with sensible defaults: build-id read from the running binary,
    /// a 128-crumb recorder, no-op redactor, panic hook enabled.
    pub fn new(
        project: impl Into<String>,
        version: impl Into<String>,
        reports_dir: impl Into<PathBuf>,
    ) -> Self {
        Config {
            project: project.into(),
            version: version.into(),
            git_sha: None,
            build_id: build_id::read_self(),
            reports_dir: reports_dir.into(),
            breadcrumb_capacity: 128,
            features: Vec::new(),
            retention: writer::Retention::default(),
            // 256 MiB: big enough for a realistic corrupt store, small enough
            // that a handful of them cannot fill a user's disk.
            preserve_max_bytes: 256 * 1024 * 1024,
            redactor: Box::new(NoopRedactor),
            #[cfg(feature = "shared-ring")]
            shared_ring: None,
            install_panic_hook: true,
            // Off by default — see the field docs. Arming this without the
            // matching `run_crash_monitor_if_env()` call in `main` fork-bombs
            // the host.
            install_native_crash_handler: false,
        }
    }

    #[must_use]
    pub fn git_sha(mut self, sha: impl Into<String>) -> Self {
        self.git_sha = Some(sha.into());
        self
    }

    #[must_use]
    pub fn breadcrumb_capacity(mut self, n: usize) -> Self {
        self.breadcrumb_capacity = n;
        self
    }

    /// Record the build's enabled feature flags on every report.
    #[must_use]
    pub fn features<I, S>(mut self, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.features = features.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn retention(mut self, retention: writer::Retention) -> Self {
        self.retention = retention;
        self
    }

    #[must_use]
    pub fn preserve_max_bytes(mut self, bytes: u64) -> Self {
        self.preserve_max_bytes = bytes;
        self
    }

    #[must_use]
    pub fn redactor(mut self, redactor: Box<dyn Redactor>) -> Self {
        self.redactor = redactor;
        self
    }

    /// Attach a shared-memory breadcrumb ring keyed to the artifact, so reports
    /// can carry crumbs recorded by *other* processes touching the same store.
    #[cfg(feature = "shared-ring")]
    #[must_use]
    pub fn shared_ring(mut self, ring: std::sync::Arc<shared_ring::SharedRing>) -> Self {
        self.shared_ring = Some(ring);
        self
    }

    #[must_use]
    pub fn install_panic_hook(mut self, yes: bool) -> Self {
        self.install_panic_hook = yes;
        self
    }

    #[must_use]
    pub fn install_native_crash_handler(mut self, yes: bool) -> Self {
        self.install_native_crash_handler = yes;
        self
    }
}

static CONFIG: OnceLock<Config> = OnceLock::new();

/// Initialize the recorder for this process. Idempotent: the first call wins;
/// later calls are ignored (returns `false`).
///
/// Sizes and starts the flight recorder, optionally installs the panic hook,
/// and stores the config used by [`Capture::emit`].
pub fn init(config: Config) -> bool {
    breadcrumbs::init(config.breadcrumb_capacity);
    let install_hook = config.install_panic_hook;
    if CONFIG.set(config).is_err() {
        return false;
    }
    if install_hook {
        panic::install_hook();
    }
    #[cfg(feature = "native-crash")]
    if let Some(cfg) = CONFIG.get()
        && cfg.install_native_crash_handler
    {
        native::install(cfg);
    }
    true
}

/// Divert to the native-crash monitor loop when this process was spawned as one
/// (the `native-crash` feature's monitor). Returns `false` in a normal process;
/// in the monitor it runs to completion and exits without returning.
///
/// **Call this as the first statement in `main`**, before argument parsing or
/// any other work, whenever [`Config::install_native_crash_handler`] is enabled:
///
/// ```no_run
/// fn main() {
///     if faultbox::run_crash_monitor_if_env() {
///         return;
///     }
///     // ...normal startup
/// }
/// ```
///
/// The monitor is a re-exec of this same binary, so this call is what
/// distinguishes "I am the monitor" from "I am the application". Omitting it
/// while the handler is armed makes every spawned monitor start the application
/// again — which spawns another monitor, exponentially. [`init`] detects that
/// situation and aborts the duplicate rather than letting it multiply, but the
/// only correct fix is this call.
///
/// A no-op returning `false` when the `native-crash` feature is disabled, so the
/// call site stays identical regardless of feature selection.
// The example deliberately spells out `fn main`: *where* in `main` this call
// goes is the thing being documented, and a fragment cannot show that.
#[allow(clippy::needless_doctest_main)]
#[must_use]
pub fn run_crash_monitor_if_env() -> bool {
    #[cfg(feature = "native-crash")]
    {
        native::run_crash_monitor_if_env()
    }
    #[cfg(not(feature = "native-crash"))]
    {
        false
    }
}

/// The active config, if [`init`] has run.
#[must_use]
pub fn config() -> Option<&'static Config> {
    CONFIG.get()
}

/// Unix-epoch milliseconds now. Infallible: falls back to `0` if the clock is
/// before the epoch (never in practice).
///
/// On `wasm32-unknown-unknown` there is no clock at all — `SystemTime::now()`
/// *panics* there with "time not implemented on this platform", and it panics
/// inside the call, so no error handling around it helps. Because a breadcrumb
/// is recorded on ordinary success paths, that would make merely linking this
/// crate into a wasm build fatal the first time any library records a crumb.
/// A monotonic counter is substituted: the values are not wall-clock times, but
/// they order breadcrumbs correctly, which is all a trail needs. Reports cannot
/// be written on that target anyway — there is no filesystem — so nothing else
/// observes them.
///
/// `wasm32-wasip1`/`wasip2` have a real clock and take the normal path.
#[must_use]
pub fn now_ms() -> u128 {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TICK: AtomicU64 = AtomicU64::new(0);
        u128::from(TICK.fetch_add(1, Ordering::Relaxed))
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }
}

/// A pending artifact to copy into the report directory on [`Capture::emit`].
struct PendingArtifact {
    kind: String,
    src: PathBuf,
    name: String,
    note: Option<String>,
}

/// Builder for a single report. Construct at a failure site, attach context,
/// then [`emit`](Capture::emit).
pub struct Capture {
    kind: EventKind,
    message: String,
    error_chain: Vec<String>,
    domain_kind: Option<String>,
    domain_key: String,
    domain: serde_json::Value,
    backtrace: Vec<Frame>,
    artifacts: Vec<PendingArtifact>,
}

impl Capture {
    /// Begin a capture of `kind` with a one-line `message`.
    pub fn new(kind: EventKind, message: impl Into<String>) -> Self {
        Capture {
            kind,
            message: message.into(),
            error_chain: Vec::new(),
            domain_kind: None,
            domain_key: String::new(),
            domain: serde_json::Value::Null,
            backtrace: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    /// Record the outer-to-inner `Display` chain of an error (e.g. by walking
    /// [`std::error::Error::source`]).
    #[must_use]
    pub fn error_chain<I, S>(mut self, chain: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.error_chain = chain.into_iter().map(Into::into).collect();
        self
    }

    /// Attach project-specific forensic context and adopt its grouping key.
    ///
    /// # Panics
    ///
    /// Never — including when the [`DomainContext`] implementation itself
    /// panics. Serializing forensic context is exactly the code most likely to
    /// misbehave while a system is already failing: it reaches into the very
    /// structures whose corruption is being reported, and an index or `unwrap`
    /// that holds in a healthy process need not hold in this one. Losing the
    /// context is a worse report; taking the process down at the detection site
    /// is a worse outcome.
    ///
    /// A panicking implementation therefore leaves the payload empty and the
    /// capture usable, so the report still records that the site fired.
    #[must_use]
    pub fn domain(mut self, ctx: &dyn DomainContext) -> Self {
        let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (
                ctx.domain_kind().to_owned(),
                ctx.grouping_key(),
                ctx.to_json(),
            )
        }));
        if let Ok((kind, key, json)) = captured {
            self.domain_kind = Some(kind);
            self.domain_key = key;
            self.domain = json;
        }
        self
    }

    /// Capture a backtrace at this point.
    #[must_use]
    pub fn with_backtrace(mut self) -> Self {
        let bt = std::backtrace::Backtrace::force_capture();
        self.backtrace = panic::frames_from_backtrace(&bt);
        self
    }

    /// Attach pre-built backtrace frames (used by the panic hook).
    #[must_use]
    pub fn backtrace_frames(mut self, frames: Vec<Frame>) -> Self {
        self.backtrace = frames;
        self
    }

    /// Preserve a file or directory alongside the report (copied in on
    /// `emit`) — e.g. a snapshot of a corrupt store for offline `fsck`.
    #[must_use]
    pub fn preserve(
        mut self,
        artifact_kind: impl Into<String>,
        src: impl Into<PathBuf>,
        name: impl Into<String>,
        note: Option<String>,
    ) -> Self {
        self.artifacts.push(PendingArtifact {
            kind: artifact_kind.into(),
            src: src.into(),
            name: name.into(),
            note,
        });
        self
    }

    /// Build, persist, and return the report directory. Returns `None` if the
    /// recorder was never [`init`]ialized or the write failed — never panics,
    /// so it is safe inside a panic hook.
    ///
    /// Reports **coalesce by fingerprint**: repeated captures of one bug land in
    /// the same directory, bumping [`Report::occurrences`] and refreshing
    /// `latest.json`, rather than writing a directory per occurrence.
    ///
    /// # Panics
    ///
    /// Never. That is a guarantee, not an aspiration: this runs at a detection
    /// site in a process that is already in trouble, and often from inside the
    /// panic hook, where a second panic is an abort that destroys the report.
    ///
    /// Making it true takes more than avoiding `unwrap` in this crate, because
    /// the capture path calls *adopter* code — [`Redactor::redact`] on every
    /// string, and `Redactor::redact_json` over the domain payload. A panicking
    /// redactor would otherwise take the application down from a logging-shaped
    /// call, so the whole capture is unwind-guarded and a panic simply yields
    /// `None`.
    ///
    /// Note the direction of that failure: a panic part-way through redaction
    /// abandons the report entirely rather than writing what had been redacted
    /// so far. A missing report costs a debugging session; a half-redacted one
    /// costs the secret.
    ///
    /// Nothing can be done about a build using `panic = "abort"`, where no
    /// unwind is catchable — there, an adopter's redactor must not panic.
    #[must_use]
    pub fn emit(self) -> Option<PathBuf> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || self.emit_inner()))
            .unwrap_or(None)
    }

    fn emit_inner(self) -> Option<PathBuf> {
        let cfg = CONFIG.get()?;
        let redactor = cfg.redactor.as_ref();

        let message = redactor.redact(&self.message);
        let error_chain: Vec<String> = self
            .error_chain
            .iter()
            .map(|s| redactor.redact(s))
            .collect();
        let mut domain = self.domain;
        redactor.redact_json(&mut domain);
        let breadcrumbs = redacted_breadcrumbs(cfg, redactor);
        // A backtrace is rendered text, and what it renders is the build
        // machine's absolute source paths — `/home/<user>/…` and the crate
        // paths under it — plus whatever an adopter's symbol names happen to
        // spell. A report is meant to be submittable, so this goes through the
        // redactor like every other string, rather than being the one channel
        // that bypasses it.
        let backtrace: Vec<Frame> = self
            .backtrace
            .into_iter()
            .map(|frame| Frame {
                address: frame.address,
                symbol: frame.symbol.as_deref().map(|s| redactor.redact(s)),
                location: frame.location.as_deref().map(|l| redactor.redact(l)),
            })
            .collect();

        // Fingerprint by (project, kind, detection site, failure-class key) so
        // the same bug at the same site collapses to one group, while distinct
        // sites sharing a key stay separate.
        let domain_facet = match &self.domain_kind {
            Some(kind) => format!("{kind}|{}", self.domain_key),
            None => self.domain_key.clone(),
        };
        let fingerprint = writer::fingerprint(&cfg.project, self.kind, &domain_facet, &message);

        let now = now_ms();
        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            kind: self.kind,
            message,
            meta: Meta {
                project: cfg.project.clone(),
                version: cfg.version.clone(),
                git_sha: cfg.git_sha.clone(),
                build_id: cfg.build_id.clone(),
                captured_at_ms: now,
                pid: std::process::id(),
                ppid: Meta::current_ppid(),
                // Thread names are adopter-chosen and routinely carry the work
                // item they were spawned for — a tenant, an account, a path.
                thread: Meta::current_thread_name().map(|t| redactor.redact(&t)),
            },
            error_chain,
            backtrace,
            breadcrumbs,
            domain_kind: self.domain_kind,
            domain,
            env: Env::with_features(cfg.features.clone()),
            artifacts: Vec::new(),
            fingerprint,
            occurrences: 1,
            first_seen_ms: now,
            last_seen_ms: now,
        };

        let dir = writer::ensure_group_dir(&cfg.reports_dir, &report.fingerprint).ok()?;

        // Digest and copy artifacts BEFORE taking the lock. Preserving a store
        // can move gigabytes; doing it under the lock would routinely outlast
        // the staleness window, and a competing process would steal the lock
        // and copy over us mid-write.
        let staged: Vec<_> = self
            .artifacts
            .iter()
            .map(|pending| {
                (
                    pending,
                    writer::stage_artifact(
                        &dir,
                        &pending.src,
                        &pending.name,
                        cfg.preserve_max_bytes,
                    ),
                )
            })
            .collect();

        // Everything from here is fast, so the lock is held only briefly. A
        // supervisor restarting a crashing daemon has several processes racing
        // on exactly this directory.
        //
        // Failing to take it means giving up *after* staging, which means
        // throwing the staged bytes away. Staging names are unique, so an
        // abandoned one is never overwritten by the next attempt — under a crash
        // loop, silently leaving them would be an unbounded leak inside the very
        // directory retention exists to bound.
        let _lock = match writer::lock_group(&dir) {
            Ok(lock) => lock,
            Err(_) => {
                for (_, staged) in staged {
                    if let Ok(staged) = staged {
                        staged.discard();
                    }
                }
                return None;
            }
        };
        for (pending, staged) in staged {
            report
                .artifacts
                .push(commit_pending(&dir, pending, staged, redactor));
        }
        writer::commit_into(&dir, &mut report).ok()?;
        drop(_lock);
        writer::prune(&cfg.reports_dir, cfg.retention, &dir);
        Some(dir)
    }
}

/// Preserve one pending artifact, turning every outcome — including failure and
/// refusal — into an [`Artifact`] entry. An artifact that could not be captured
/// is recorded as such, because an analyst reading the report needs to know the
/// snapshot is missing rather than infer it from an absent field.
///
/// Every note is built through `redactor`. Notes are the one report field
/// assembled *after* the redaction pass, and they interpolate exactly the things
/// redaction exists to remove: the adopter's free-text note, the source path of
/// the artifact (an absolute path under the user's home), and an `io::Error`
/// whose `Display` also renders that path.
fn commit_pending(
    dir: &std::path::Path,
    pending: &PendingArtifact,
    staged: std::io::Result<writer::Staged>,
    redactor: &dyn Redactor,
) -> Artifact {
    let note = |extra: Option<&str>| {
        let text = match (&pending.note, extra) {
            (Some(n), Some(extra)) => format!("{n} ({extra})"),
            (Some(n), None) => n.clone(),
            (None, Some(extra)) => extra.to_owned(),
            (None, None) => return None,
        };
        Some(redactor.redact(&text))
    };
    match staged.and_then(|s| writer::commit_artifact(dir, s)) {
        Ok(writer::Preserved::Copied { rel, bytes, digest }) => Artifact {
            kind: pending.kind.clone(),
            rel_path: rel,
            note: note(None),
            digest: Some(digest),
            bytes: Some(bytes),
        },
        Ok(writer::Preserved::Reused { rel, bytes, digest }) => Artifact {
            kind: pending.kind.clone(),
            rel_path: rel,
            note: note(Some("unchanged since an earlier occurrence of this bug")),
            digest: Some(digest),
            bytes: Some(bytes),
        },
        Ok(writer::Preserved::TooLarge { bytes, limit }) => Artifact {
            kind: pending.kind.clone(),
            rel_path: String::new(),
            note: note(Some(&format!(
                "NOT PRESERVED: {bytes} bytes exceeds the {limit}-byte cap; \
                 the source was left in place at {}",
                pending.src.display()
            ))),
            digest: None,
            bytes: Some(bytes),
        },
        Err(e) => Artifact {
            kind: pending.kind.clone(),
            rel_path: String::new(),
            note: note(Some(&format!("NOT PRESERVED: {e}"))),
            digest: None,
            bytes: None,
        },
    }
}

/// Snapshot the flight recorder — merged with the shared, artifact-keyed ring
/// when one is configured — and redact each crumb's message and fields.
///
/// Crumbs this process recorded appear in *both* rings (they are written to
/// both), so the shared ring's contribution is restricted to *other* processes.
/// Those are the ones the local recorder structurally cannot know about, and
/// the reason the shared ring exists: the writes that caused a corruption
/// usually happened somewhere else.
fn redacted_breadcrumbs(_cfg: &Config, redactor: &dyn Redactor) -> Vec<breadcrumbs::Breadcrumb> {
    let mut crumbs = breadcrumbs::snapshot();
    for c in &mut crumbs {
        c.message = redactor.redact(&c.message);
        redactor.redact_json(&mut c.fields);
    }

    #[cfg(feature = "shared-ring")]
    if let Some(ring) = &_cfg.shared_ring {
        let me = std::process::id();
        // Ring crumbs were redacted on the way *in* (see `breadcrumbs::record`),
        // so they are appended after the loop above rather than run through the
        // redactor a second time — a caller's redactor is not required to be
        // idempotent.
        crumbs.extend(
            ring.snapshot()
                .into_iter()
                .filter(|c| c.pid != Some(me) && c.pid.is_some()),
        );
        // Interleave the two trails into one causal sequence.
        crumbs.sort_by_key(|c| c.ts_ms);
    }

    crumbs
}

/// Walk an [`std::error::Error`]'s `source` chain into `Display` strings,
/// outer-to-inner — a convenience for [`Capture::error_chain`].
#[must_use]
pub fn error_chain_of(err: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut out = vec![err.to_string()];
    let mut src = err.source();
    while let Some(e) = src {
        out.push(e.to_string());
        src = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Inner;
    impl std::fmt::Display for Inner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "inner cause")
        }
    }
    impl std::error::Error for Inner {}

    #[derive(Debug)]
    struct Outer(Inner);
    impl std::fmt::Display for Outer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "outer failure")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_of_walks_sources_outer_to_inner() {
        let e = Outer(Inner);
        let chain = error_chain_of(&e);
        assert_eq!(chain, vec!["outer failure", "inner cause"]);
    }

    #[test]
    fn now_ms_is_positive() {
        assert!(now_ms() > 0);
    }

    /// Regression guard for a fork bomb.
    ///
    /// The native-crash monitor is a re-exec of the host binary that only
    /// becomes a monitor if `main` calls `run_crash_monitor_if_env()`. When this
    /// defaulted to `true`, merely enabling the Cargo feature armed it — so any
    /// host without that call (every test binary, for one) spawned a child that
    /// re-ran the application, which spawned another child, exponentially. It
    /// produced 2000+ runaway processes on the first run.
    ///
    /// Arming it must stay an explicit, deliberate opt-in, regardless of which
    /// Cargo features happen to be enabled.
    #[test]
    fn native_crash_handler_is_never_armed_by_default() {
        let cfg = Config::new("t", "0.1.0", "/tmp/faultbox-test-reports");
        assert!(
            !cfg.install_native_crash_handler,
            "enabling the `native-crash` feature must not arm the handler; \
             the host must opt in *and* call run_crash_monitor_if_env()"
        );
    }
}

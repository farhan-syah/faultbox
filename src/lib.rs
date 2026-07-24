// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blackbox` — a production black-box recorder for the NodeDB-lab projects.
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
pub mod panic;
pub mod report;
pub mod writer;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub use context::{Adhoc, DomainContext, NoopRedactor, Redactor};
pub use report::{Artifact, Env, EventKind, Frame, Meta, Report, SCHEMA_VERSION};

/// Re-exported so adopters can build [`DomainContext::to_json`] payloads
/// (`blackbox::serde_json::json!{…}`) without taking their own dependency.
pub use serde_json;

/// Process-wide configuration, set once via [`init`].
pub struct Config {
    /// Adopting project name, e.g. `"pagedb"`.
    pub project: String,
    /// Package semver.
    pub version: String,
    /// Git commit of the build, if known (typically `option_env!` from a build
    /// script). `None` is acceptable but weakens traceability.
    pub git_sha: Option<String>,
    /// GNU build-id; defaults to the running binary's via [`build_id::read_self`].
    pub build_id: Option<String>,
    /// Directory reports are written under, e.g. `~/.pagedb/crash-reports`.
    pub reports_dir: PathBuf,
    /// Flight-recorder capacity (number of breadcrumbs retained).
    pub breadcrumb_capacity: usize,
    /// Redactor applied to every string entering a report. Defaults to a no-op;
    /// production adopters MUST supply a real one.
    pub redactor: Box<dyn Redactor>,
    /// Whether [`init`] installs the panic hook.
    pub install_panic_hook: bool,
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
            redactor: Box::new(NoopRedactor),
            install_panic_hook: true,
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

    #[must_use]
    pub fn redactor(mut self, redactor: Box<dyn Redactor>) -> Self {
        self.redactor = redactor;
        self
    }

    #[must_use]
    pub fn install_panic_hook(mut self, yes: bool) -> Self {
        self.install_panic_hook = yes;
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
    true
}

/// The active config, if [`init`] has run.
#[must_use]
pub fn config() -> Option<&'static Config> {
    CONFIG.get()
}

/// Unix-epoch milliseconds now. Falls back to `0` if the clock is before the
/// epoch (never in practice) so callers stay infallible.
#[must_use]
pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
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
    #[must_use]
    pub fn domain(mut self, ctx: &dyn DomainContext) -> Self {
        self.domain_kind = Some(ctx.domain_kind().to_owned());
        self.domain_key = ctx.grouping_key();
        self.domain = ctx.to_json();
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
    #[must_use]
    pub fn emit(self) -> Option<PathBuf> {
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
        let breadcrumbs = redacted_breadcrumbs(redactor);

        // Fingerprint by (project, kind, detection site, failure-class key) so
        // the same bug at the same site collapses to one group, while distinct
        // sites sharing a key stay separate.
        let domain_facet = match &self.domain_kind {
            Some(kind) => format!("{kind}|{}", self.domain_key),
            None => self.domain_key.clone(),
        };
        let fingerprint = writer::fingerprint(&cfg.project, self.kind, &domain_facet, &message);

        let mut report = Report {
            schema_version: SCHEMA_VERSION,
            kind: self.kind,
            message,
            meta: Meta {
                project: cfg.project.clone(),
                version: cfg.version.clone(),
                git_sha: cfg.git_sha.clone(),
                build_id: cfg.build_id.clone(),
                captured_at_ms: now_ms(),
                pid: std::process::id(),
            },
            error_chain,
            backtrace: self.backtrace,
            breadcrumbs,
            domain_kind: self.domain_kind,
            domain,
            env: Env::current(),
            artifacts: Vec::new(),
            fingerprint,
        };

        let dir = writer::report_dir_for(&cfg.reports_dir, &report).ok()?;
        for pending in &self.artifacts {
            match writer::preserve_artifact(&dir, &pending.src, &pending.name) {
                Ok(rel) => report.artifacts.push(Artifact {
                    kind: pending.kind.clone(),
                    rel_path: rel,
                    note: pending.note.clone(),
                }),
                Err(_) => { /* best-effort: a missing artifact must not lose the report */ }
            }
        }
        writer::write_report_json(&dir, &report).ok()?;
        Some(dir)
    }
}

/// Snapshot the flight recorder and redact each crumb's message + fields.
fn redacted_breadcrumbs(redactor: &dyn Redactor) -> Vec<breadcrumbs::Breadcrumb> {
    let mut crumbs = breadcrumbs::snapshot();
    for c in &mut crumbs {
        c.message = redactor.redact(&c.message);
        redactor.redact_json(&mut c.fields);
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
}

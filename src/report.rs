// SPDX-License-Identifier: MIT OR Apache-2.0

//! The portable report schema.
//!
//! A [`Report`] is the single artifact every failure class serializes to —
//! panics, native crashes, detected corruption, and invariant violations all
//! produce the same shape so downstream tooling (bug reports, symbolication,
//! grouping) is uniform across every project that adopts `blackbox`.
//!
//! The schema is versioned ([`SCHEMA_VERSION`]): readers must tolerate unknown
//! trailing fields and gate on the version before interpreting semantics.

use serde::{Deserialize, Serialize};

use crate::breadcrumbs::Breadcrumb;

/// On-disk report schema version. Bump on any breaking shape change; add fields
/// additively without a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// The failure class a report describes.
///
/// A single enum across projects keeps grouping and triage uniform. The
/// storage-specific classes (`Corruption`, `InvariantViolation`) are the reason
/// this exists over a panic-only crash reporter: they are usually *returned
/// errors*, never crashes, so nothing else would capture them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A Rust panic (caught by the installed panic hook).
    Panic,
    /// A native/hardware crash (SIGSEGV, abort, stack overflow) captured
    /// out-of-process as a minidump. `blackbox` records the metadata; the
    /// minidump itself is an [`Artifact`].
    NativeCrash,
    /// Detected data corruption (checksum/AEAD failure, structural violation).
    /// Carries rich domain context and usually a preserved artifact.
    Corruption,
    /// A runtime invariant/assertion that must hold was found violated — caught
    /// cheaply in production rather than only under a dev-only checker.
    InvariantViolation,
    /// A recoverable error deemed report-worthy by the emitting site.
    Error,
}

impl EventKind {
    /// Stable lowercase slug used in fingerprints and paths.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            EventKind::Panic => "panic",
            EventKind::NativeCrash => "native_crash",
            EventKind::Corruption => "corruption",
            EventKind::InvariantViolation => "invariant_violation",
            EventKind::Error => "error",
        }
    }
}

/// Identity of the build and process that produced the report — everything a
/// bug report needs to locate the exact code and, with the symbol store, to
/// symbolicate offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// Adopting project name, e.g. `"pagedb"`.
    pub project: String,
    /// Package semver, e.g. `"0.1.0"`.
    pub version: String,
    /// Git commit the build came from, if known.
    pub git_sha: Option<String>,
    /// GNU build-id (hex) of the running binary — the symbolication key.
    pub build_id: Option<String>,
    /// Unix-epoch milliseconds when the report was captured.
    pub captured_at_ms: u128,
    /// Process id, for correlating with external logs.
    pub pid: u32,
}

/// A single frame's identity. Function names are present only when the build
/// retained line tables; the `address` + `Meta::build_id` always allow
/// server-side symbolication against the release's stored debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Instruction pointer / return address (module-relative when resolvable).
    pub address: Option<u64>,
    /// Demangled symbol name, if line tables were present.
    pub symbol: Option<String>,
    /// `file:line`, if available.
    pub location: Option<String>,
}

/// A pointer to a preserved on-disk artifact (a minidump, or a snapshot of a
/// corrupt store) that travels with the report for offline analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Free-form kind, e.g. `"minidump"`, `"pagedb-store"`.
    pub kind: String,
    /// Path relative to the report directory.
    pub rel_path: String,
    /// Human note, e.g. how to inspect it (`"pagedb-fsck --deep …"`).
    pub note: Option<String>,
}

/// Coarse host/runtime facts. Deliberately free of user data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Env {
    pub os: String,
    pub arch: String,
    /// Compile-time feature flags the adopter chose to record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

impl Env {
    /// Capture the coarse target facts known at compile time.
    #[must_use]
    pub fn current() -> Self {
        Env {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            features: Vec::new(),
        }
    }
}

/// The portable report. Serialized as `report.json` in the report directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Always [`SCHEMA_VERSION`] at write time.
    pub schema_version: u32,
    /// What class of failure this is.
    pub kind: EventKind,
    /// One-line human summary (already redacted).
    pub message: String,
    /// Build/process identity.
    pub meta: Meta,
    /// Outer-to-inner error `Display` chain (already redacted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_chain: Vec<String>,
    /// Captured backtrace frames (may be empty when disabled/unavailable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backtrace: Vec<Frame>,
    /// The flight-recorder trail leading up to the failure (already redacted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub breadcrumbs: Vec<Breadcrumb>,
    /// The domain site tag (e.g. `"pagedb.dangling_child"`) when domain context
    /// was attached — records *where* the failure was detected, complementing
    /// the payload in [`domain`](Self::domain) and feeding the fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_kind: Option<String>,
    /// Domain-specific forensic context (from a [`crate::DomainContext`]),
    /// already redacted. `null` when none was attached.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub domain: serde_json::Value,
    /// Coarse environment facts.
    pub env: Env,
    /// Preserved artifacts travelling with the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    /// Stable grouping/dedup key (see [`crate::fingerprint`]).
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_roundtrips_through_json() {
        let report = Report {
            schema_version: SCHEMA_VERSION,
            kind: EventKind::Corruption,
            message: "AEAD/MAC verification failed on read".to_owned(),
            meta: Meta {
                project: "pagedb".to_owned(),
                version: "0.1.0".to_owned(),
                git_sha: Some("abc123".to_owned()),
                build_id: Some("deadbeef".to_owned()),
                captured_at_ms: 1,
                pid: 42,
            },
            error_chain: vec!["ChecksumFailure".to_owned()],
            backtrace: vec![Frame {
                address: Some(0x1000),
                symbol: None,
                location: None,
            }],
            breadcrumbs: Vec::new(),
            domain_kind: Some("pagedb.dangling_child".to_owned()),
            domain: serde_json::json!({ "page_id": 828, "kind": "0x09" }),
            env: Env::current(),
            artifacts: vec![Artifact {
                kind: "pagedb-store".to_owned(),
                rel_path: "store.corrupt".to_owned(),
                note: Some("pagedb-fsck --deep".to_owned()),
            }],
            fingerprint: "ff00ff00".to_owned(),
        };

        let json = serde_json::to_string(&report).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, EventKind::Corruption);
        assert_eq!(back.domain["page_id"], 828);
        assert_eq!(back.artifacts.len(), 1);
        assert_eq!(back.fingerprint, "ff00ff00");
    }

    #[test]
    fn empty_collections_are_omitted_from_json() {
        let report = Report {
            schema_version: SCHEMA_VERSION,
            kind: EventKind::Panic,
            message: "boom".to_owned(),
            meta: Meta {
                project: "ma8e".to_owned(),
                version: "0.1.0".to_owned(),
                git_sha: None,
                build_id: None,
                captured_at_ms: 0,
                pid: 1,
            },
            error_chain: Vec::new(),
            backtrace: Vec::new(),
            breadcrumbs: Vec::new(),
            domain_kind: None,
            domain: serde_json::Value::Null,
            env: Env::current(),
            artifacts: Vec::new(),
            fingerprint: "0".to_owned(),
        };
        let json = serde_json::to_string(&report).unwrap();
        // Skipped-when-empty fields must not appear.
        assert!(!json.contains("error_chain"));
        assert!(!json.contains("breadcrumbs"));
        assert!(!json.contains("\"domain\""));
        assert!(!json.contains("artifacts"));
    }
}

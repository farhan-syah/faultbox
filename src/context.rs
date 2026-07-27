// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extension points every adopting project implements.
//!
//! [`DomainContext`] injects project-specific forensic fields — whatever the
//! adopting project needs to understand its own failure, such as the offending
//! record, a header dump, or free-list statistics — and, crucially, a stable
//! [`DomainContext::grouping_key`] so like failures fingerprint together across
//! machines.
//!
//! [`Redactor`] strips user data from every string that enters a report —
//! messages, error chains, breadcrumbs, and domain values — so reports are safe
//! to bundle and submit. Reports carry structural/diagnostic metadata only. It
//! lives in [`crate::redact`] and is re-exported here, where adopters have
//! always found it.

use serde::Serialize;

pub use crate::redact::{BasicRedactor, NoopRedactor, Redactor};

/// Project-specific forensic context attached to a report.
///
/// Implementors return only structural/diagnostic data — never user content
/// (keys, values, paths that identify user data). The `faultbox` writer applies
/// the configured [`Redactor`] to the serialized value as defence in depth.
pub trait DomainContext {
    /// Short domain tag, e.g. `"store.dangling_child"`. Becomes part of the
    /// fingerprint and groups reports by failure site. A compile-time constant.
    fn domain_kind(&self) -> &'static str;

    /// A stable identifier for *this class* of failure — NOT this instance.
    /// e.g. `"kind=0x09"` for "internal child recycled as overflow root",
    /// independent of which page ids happened to be involved. Reports sharing a
    /// `(domain_kind, grouping_key)` are the same bug.
    fn grouping_key(&self) -> String;

    /// The forensic payload, serialized into the report's `domain` field.
    fn to_json(&self) -> serde_json::Value;
}

/// Blanket helper so any `Serialize` value can be a quick domain payload when a
/// bespoke type is overkill — pair it with an explicit kind + key.
pub struct Adhoc<T: Serialize> {
    pub kind: &'static str,
    pub key: String,
    pub value: T,
}

impl<T: Serialize> DomainContext for Adhoc<T> {
    fn domain_kind(&self) -> &'static str {
        self.kind
    }
    fn grouping_key(&self) -> String {
        self.key.clone()
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.value).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adhoc_context_serializes_value() {
        let ctx = Adhoc {
            kind: "store.test",
            key: "kind=0x09".to_owned(),
            value: serde_json::json!({ "page_id": 6044 }),
        };
        assert_eq!(ctx.domain_kind(), "store.test");
        assert_eq!(ctx.grouping_key(), "kind=0x09");
        assert_eq!(ctx.to_json()["page_id"], 6044);
    }
}

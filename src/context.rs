// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extension points every adopting project implements.
//!
//! [`DomainContext`] injects project-specific forensic fields (pagedb: the
//! failing page, header, free-list stats; ma8e: config digest) and, crucially,
//! a stable [`DomainContext::grouping_key`] so like failures fingerprint
//! together across machines.
//!
//! [`Redactor`] strips user data from every string that enters a report —
//! messages, error chains, breadcrumbs, and domain values — so reports are safe
//! to bundle and submit. Reports carry structural/diagnostic metadata only.

use serde::Serialize;

/// Project-specific forensic context attached to a report.
///
/// Implementors return only structural/diagnostic data — never user content
/// (keys, values, paths that identify user data). The `blackbox` writer applies
/// the configured [`Redactor`] to the serialized value as defence in depth.
pub trait DomainContext {
    /// Short domain tag, e.g. `"pagedb.dangling_child"`. Becomes part of the
    /// fingerprint and groups reports by failure site.
    fn domain_kind(&self) -> &str;

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
    fn domain_kind(&self) -> &str {
        self.kind
    }
    fn grouping_key(&self) -> String {
        self.key.clone()
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.value).unwrap_or(serde_json::Value::Null)
    }
}

/// Removes user data from report strings. The default [`NoopRedactor`] changes
/// nothing; production adopters supply one backed by their own pattern set
/// (ma8e reuses its `Redactor`).
pub trait Redactor: Send + Sync {
    /// Return `input` with any sensitive substrings replaced.
    fn redact(&self, input: &str) -> String;

    /// Redact every string node within a JSON value, structure preserved.
    fn redact_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                let red = self.redact(s);
                if red != *s {
                    *s = red;
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_json(item);
                }
            }
            serde_json::Value::Object(map) => {
                for (_k, v) in map.iter_mut() {
                    self.redact_json(v);
                }
            }
            _ => {}
        }
    }
}

/// A redactor that passes everything through unchanged.
pub struct NoopRedactor;

impl Redactor for NoopRedactor {
    fn redact(&self, input: &str) -> String {
        input.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MaskDigits;
    impl Redactor for MaskDigits {
        fn redact(&self, input: &str) -> String {
            input
                .chars()
                .map(|c| if c.is_ascii_digit() { '#' } else { c })
                .collect()
        }
    }

    #[test]
    fn redact_json_walks_nested_strings_only() {
        let mut v = serde_json::json!({
            "path": "/home/u42/secret",
            "page_id": 828,
            "nested": ["tok-99", { "k": "v7" }],
        });
        MaskDigits.redact_json(&mut v);
        assert_eq!(v["path"], "/home/u##/secret");
        // Numbers are untouched (only string nodes are redacted).
        assert_eq!(v["page_id"], 828);
        assert_eq!(v["nested"][0], "tok-##");
        assert_eq!(v["nested"][1]["k"], "v#");
    }

    #[test]
    fn adhoc_context_serializes_value() {
        let ctx = Adhoc {
            kind: "pagedb.test",
            key: "kind=0x09".to_owned(),
            value: serde_json::json!({ "page_id": 6044 }),
        };
        assert_eq!(ctx.domain_kind(), "pagedb.test");
        assert_eq!(ctx.grouping_key(), "kind=0x09");
        assert_eq!(ctx.to_json()["page_id"], 6044);
    }
}

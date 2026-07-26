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
//! to bundle and submit. Reports carry structural/diagnostic metadata only.

use serde::Serialize;

/// Project-specific forensic context attached to a report.
///
/// Implementors return only structural/diagnostic data — never user content
/// (keys, values, paths that identify user data). The `blackbox` writer applies
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

/// Removes user data from report strings.
///
/// The default [`NoopRedactor`] changes nothing. [`BasicRedactor`] covers the
/// common leaks (home directory, secret-looking assignments, emails) and is the
/// right starting point; a project with its own pattern set implements this
/// trait over it.
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

/// A ready-to-use redactor covering what actually leaks from a storage engine's
/// error messages: the user's home directory, and anything that looks like a
/// credential.
///
/// This exists because "production adopters MUST supply a real one" is advice
/// that does not survive contact with a release deadline — a default that is
/// safe beats a default that is correct only if someone remembers. It is a
/// starting point, not a compliance boundary: a project handling regulated data
/// should compose its own [`Redactor`] on top.
///
/// What it does:
///
/// - Replaces the home directory prefix with `~`, so `/home/ada/db/main.db`
///   becomes `~/db/main.db` — the structure a maintainer needs, without the
///   username.
/// - Masks `key=value` pairs whose key names a secret (`password`, `token`,
///   `secret`, `api_key`, `authorization`, …).
/// - Masks anything shaped like an email address.
pub struct BasicRedactor {
    home: Option<String>,
}

impl BasicRedactor {
    /// Build a redactor for the current user's environment.
    #[must_use]
    pub fn new() -> Self {
        // `HOME` on unix, `USERPROFILE` on Windows. Absent in many daemon
        // environments, which simply means there is no prefix to strip.
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .filter(|h| h.len() > 1);
        BasicRedactor { home }
    }

    /// Override the home directory to strip. Mainly for tests and for daemons
    /// that run as a service account but report on a user's data directory.
    #[must_use]
    pub fn home(mut self, home: impl Into<String>) -> Self {
        self.home = Some(home.into());
        self
    }
}

impl Default for BasicRedactor {
    fn default() -> Self {
        Self::new()
    }
}

/// The marker substituted for a redacted value. Recognised on input too, so
/// redacting an already-redacted string is a no-op.
const REDACTED: &str = "[redacted]";

/// Key fragments that mark a `key=value` pair as sensitive. Matched
/// case-insensitively against the key.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "private_key",
];

impl Redactor for BasicRedactor {
    fn redact(&self, input: &str) -> String {
        let mut out = match &self.home {
            Some(home) => input.replace(home.as_str(), "~"),
            None => input.to_owned(),
        };
        out = mask_secret_assignments(&out);
        mask_emails(&out)
    }
}

/// Replace the value in `key=value` / `key: value` pairs whose key looks like a
/// secret. The value runs to the next whitespace, quote, comma, or closing
/// bracket, which covers both prose messages and `Debug` output of a config.
fn mask_secret_assignments(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        // Does a secret key name end at this separator?
        let sep = bytes[i];
        if sep == b'=' || sep == b':' {
            if let Some(key_start) = SECRET_KEYS
                .iter()
                .filter_map(|k| {
                    let end = i;
                    let start = end.checked_sub(k.len())?;
                    (lower.get(start..end)? == *k
                        && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric()))
                    .then_some(start)
                })
                .max()
            {
                // Emit up to and including the separator (already in `out`
                // except for the separator itself).
                let _ = key_start;
                out.push(sep as char);
                i += 1;
                // Skip whitespace and an opening quote.
                while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'"') {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                // Already redacted (this string is being redacted twice, e.g. a
                // message that passed through a caller's own redactor first).
                // Copy the marker through rather than treating `[redacted]` as
                // a fresh value and emitting `[redacted]]`.
                if input[i..].starts_with(REDACTED) {
                    out.push_str(REDACTED);
                    i += REDACTED.len();
                    continue;
                }
                let value_start = i;
                while i < bytes.len() && !is_value_terminator(bytes[i]) {
                    i += 1;
                }
                if i > value_start {
                    out.push_str(REDACTED);
                }
                continue;
            }
        }
        // Copy the whole UTF-8 character through.
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&input[start..i]);
    }
    out
}

fn is_value_terminator(b: u8) -> bool {
    matches!(b, b' ' | b'"' | b',' | b'}' | b')' | b']' | b'\n' | b'\t')
}

/// Replace anything shaped like `local@domain.tld`.
fn mask_emails(input: &str) -> String {
    if !input.contains('@') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    for (i, token) in input.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if looks_like_email(token) {
            out.push_str("[email]");
        } else {
            out.push_str(token);
        }
    }
    out
}

fn looks_like_email(token: &str) -> bool {
    let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '@' && c != '.');
    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
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
            kind: "store.test",
            key: "kind=0x09".to_owned(),
            value: serde_json::json!({ "page_id": 6044 }),
        };
        assert_eq!(ctx.domain_kind(), "store.test");
        assert_eq!(ctx.grouping_key(), "kind=0x09");
        assert_eq!(ctx.to_json()["page_id"], 6044);
    }

    #[test]
    fn basic_redactor_strips_the_home_directory_but_keeps_structure() {
        let r = BasicRedactor::new().home("/home/ada");
        assert_eq!(
            r.redact("failed to open /home/ada/db/main.db"),
            "failed to open ~/db/main.db",
            "the path shape a maintainer needs survives; the username does not"
        );
    }

    #[test]
    fn basic_redactor_masks_secret_assignments() {
        let r = BasicRedactor::new().home("/nonexistent");
        assert_eq!(
            r.redact("connect failed token=sk-abc123 retries=3"),
            "connect failed token=[redacted] retries=3",
            "only the secret is masked; the diagnostic field stays readable"
        );
        assert_eq!(
            r.redact("Config { password: \"hunter2\", port: 5432 }"),
            "Config { password: \"[redacted]\", port: 5432 }"
        );
        // Case-insensitive, and only on a key boundary.
        assert_eq!(r.redact("API_KEY=zzz"), "API_KEY=[redacted]");
    }

    #[test]
    fn basic_redactor_leaves_lookalike_keys_alone() {
        let r = BasicRedactor::new().home("/nonexistent");
        // `token` here is part of a longer word, not a key.
        assert_eq!(r.redact("broken_tokens=4"), "broken_tokens=4");
        assert_eq!(r.redact("page_id=828"), "page_id=828");
    }

    #[test]
    fn basic_redactor_masks_emails() {
        let r = BasicRedactor::new().home("/nonexistent");
        assert_eq!(
            r.redact("owner ada@example.com lost the write"),
            "owner [email] lost the write"
        );
        // Not an email: no dotted domain.
        assert_eq!(r.redact("user@localhost"), "user@localhost");
    }

    #[test]
    fn basic_redactor_is_idempotent() {
        let r = BasicRedactor::new().home("/home/ada");
        let once = r.redact("/home/ada/db token=abc ada@example.com");
        assert_eq!(r.redact(&once), once, "re-redacting must not corrupt");
    }
}

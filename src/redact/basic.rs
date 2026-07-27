// SPDX-License-Identifier: MIT OR Apache-2.0

//! The default redactor.

use super::edit::chain;
use super::keys::{KeyKind, classify};
use super::redactor::{REDACTED, Redactor};
use super::values::is_credential_shaped;
use super::{assignments, credentials, emails, home::Home};
use std::borrow::Cow;

/// A ready-to-use redactor covering what actually leaks from a production
/// error message: the user's home directory, anything that looks like a
/// credential, and email addresses.
///
/// This exists because "production adopters MUST supply a real one" is advice
/// that does not survive contact with a release deadline — a default that is
/// safe beats a default that is correct only if someone remembers. It is a
/// starting point, not a compliance boundary: a project handling regulated data
/// should compose its own [`Redactor`] on top.
///
/// What it does:
///
/// - Replaces the home directory with `~` and the username elsewhere in a path
///   with `~user`, so `/home/ada/db/main.db` becomes `~/db/main.db` — the
///   structure a maintainer needs, without the identity. Matching ignores case
///   and separator spelling, and respects path boundaries.
/// - Masks the value of a `key = value` pair whose key names a credential
///   (`password`, `token`, `authorization`, `x-api-key`, `AZURE_OPENAI_KEY`, …)
///   in whatever form it arrives: quoted or bare, spaced or tight, or
///   introduced by an HTTP auth scheme, where the credential follows the scheme
///   word. A composite value — `Some("…")`, `Credentials("…", "…")`,
///   `["…", "…"]`, `Secret { inner: "…" }` — has every leaf inside it masked,
///   its structure kept.
/// - Masks the same keys inside JSON — including breadcrumb fields and
///   [`DomainContext`](crate::DomainContext) payloads, where the key is an
///   object member and a per-string scan would never see it.
/// - Masks a credential that arrives with no key at all, recognised by issuer
///   prefix (`sk-`, `ghp_`, `AKIA`, …), JWT structure, or PEM block.
/// - Masks anything shaped like an email address, including keys of a map that
///   is keyed by one.
///
/// Where precision and safety conflict it over-redacts: a masked diagnostic
/// field costs a debugging session, a missed credential costs the credential.
/// Key names that are merely credential-*adjacent* (`grouping_key`, `auth`) are
/// the exception — they mask only a value that is itself credential-shaped, so
/// the fields a report is read and fingerprinted by survive.
pub struct BasicRedactor {
    home: Option<Home>,
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
            .filter(|h| h.len() > 1)
            .map(Home::new);
        BasicRedactor { home }
    }

    /// Override the home directory to strip. Mainly for tests and for daemons
    /// that run as a service account but report on a user's data directory.
    #[must_use]
    pub fn home(mut self, home: impl Into<String>) -> Self {
        self.home = Some(Home::new(home.into()));
        self
    }

    /// Replace every leaf beneath a value stored under a credential-naming key.
    /// Applied to the whole subtree, because `"authorization": ["Bearer …"]`
    /// hides the credential one level down.
    ///
    /// Masked leaves become the `[redacted]` *string* whatever they were, so
    /// `{"token": 12345}` changes type. That is deliberate: a reader learns
    /// that a value was present and withheld, which `null` — indistinguishable
    /// from a field that was never set — would not tell them. Reports are read
    /// as free-form JSON, so nothing downstream is typed on these leaves.
    fn mask_subtree(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(items) => items.iter_mut().for_each(Self::mask_subtree),
            serde_json::Value::Object(map) => {
                map.iter_mut().for_each(|(_k, v)| Self::mask_subtree(v));
            }
            serde_json::Value::Null => {}
            other => *other = serde_json::Value::String(REDACTED.to_owned()),
        }
    }
}

impl Default for BasicRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor for BasicRedactor {
    fn redact(&self, input: &str) -> String {
        let out = match &self.home {
            Some(home) => home.strip(input),
            None => Cow::Borrowed(input),
        };
        // Key-driven first: it produces `[redacted]`, which every later pass
        // recognises and leaves alone. Each pass hands back borrowed text when
        // it has nothing to change, so a string carrying no user data costs
        // exactly the one allocation this signature owes its caller.
        let out = chain(out, assignments::mask);
        let out = chain(out, credentials::mask_standalone);
        chain(out, emails::mask).into_owned()
    }

    fn redact_value_for_key(&self, key: &str, value: &mut serde_json::Value) {
        match classify(key) {
            KeyKind::Strong => Self::mask_subtree(value),
            KeyKind::Weak if credential_shaped_leaf(value) => Self::mask_subtree(value),
            _ => self.redact_json(value),
        }
    }

    fn redact_key(&self, key: &str) -> String {
        // A map keyed by user data is the one case where the key is content.
        emails::mask(key).into_owned()
    }
}

/// A weak key masks only over a credential-shaped value — the JSON counterpart
/// of the same rule the text scanner applies.
fn credential_shaped_leaf(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => is_credential_shaped(s),
        serde_json::Value::Array(items) => items.iter().any(credential_shaped_leaf),
        serde_json::Value::Object(map) => map.values().any(credential_shaped_leaf),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> BasicRedactor {
        BasicRedactor::new().home("/home/ada")
    }

    #[test]
    fn the_passes_compose_without_fighting_each_other() {
        let r = redactor();
        assert_eq!(
            r.redact("/home/ada/db token=sk-abc123 owner ada@example.com"),
            "~/db token=[redacted] owner [email]"
        );
    }

    #[test]
    fn a_weak_key_over_a_credential_shaped_json_value_still_masks() {
        let r = redactor();
        let mut v = serde_json::json!({
            "grouping_key": "kind=0x09",
            "openai_key": "sk-azure-abcdef123456",
        });
        r.redact_json(&mut v);
        assert_eq!(v["grouping_key"], "kind=0x09");
        assert_eq!(v["openai_key"], REDACTED);
    }

    #[test]
    fn a_credential_under_a_strong_key_is_masked_however_deep_it_sits() {
        let r = redactor();
        let mut v = serde_json::json!({
            "authorization": ["Bearer sk-live-1", { "raw": "sk-live-2" }],
            "page_id": 828,
        });
        r.redact_json(&mut v);
        let rendered = v.to_string();
        assert!(!rendered.contains("sk-live-1"), "{rendered}");
        assert!(!rendered.contains("sk-live-2"), "{rendered}");
        assert_eq!(v["page_id"], 828);
    }

    #[test]
    fn map_keys_that_are_addresses_are_masked() {
        let r = redactor();
        let mut v = serde_json::json!({ "ada@example.com": 3, "grace@example.com": 4 });
        r.redact_json(&mut v);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2, "no member is dropped by the collision");
        assert!(obj.contains_key("[email]"));
        assert!(obj.contains_key("[email]#2"));
    }

    #[test]
    fn a_redactor_without_a_home_still_masks_credentials() {
        let r = BasicRedactor { home: None };
        assert_eq!(r.redact("token=sk-abc123"), "token=[redacted]");
    }
}

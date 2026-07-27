// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redaction seam every adopting project may replace.

/// The marker substituted for a redacted value. Recognised on input too, so
/// redacting an already-redacted string is a no-op.
pub const REDACTED: &str = "[redacted]";

/// The marker substituted for something shaped like an email address.
pub const REDACTED_EMAIL: &str = "[email]";

/// Removes user data from report strings.
///
/// The default [`NoopRedactor`](crate::redact::NoopRedactor) changes nothing.
/// [`BasicRedactor`](crate::redact::BasicRedactor) covers the common leaks
/// (home directory, credential assignments, standalone credentials, emails)
/// and is the right starting point; a project with its own pattern set
/// implements this trait over it.
///
/// Implementors need only supply [`Redactor::redact`]. The JSON hooks have
/// defaults that walk the structure and route every string through it; a
/// redactor that can decide from a *key* — which a per-string scan never sees,
/// because the key lives in the enclosing object — overrides
/// [`Redactor::redact_value_for_key`] and [`Redactor::redact_key`].
pub trait Redactor: Send + Sync {
    /// Return `input` with any sensitive substrings replaced.
    fn redact(&self, input: &str) -> String;

    /// Redact every string node within a JSON value, structure preserved.
    ///
    /// Object members are routed through [`Redactor::redact_key`] and
    /// [`Redactor::redact_value_for_key`] so that a redactor may act on the
    /// key/value relationship, not just on isolated strings.
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
                let mut rebuilt = serde_json::Map::with_capacity(map.len());
                for (key, mut v) in std::mem::take(map) {
                    self.redact_value_for_key(&key, &mut v);
                    insert_without_clobbering(&mut rebuilt, self.redact_key(&key), v);
                }
                *map = rebuilt;
            }
            _ => {}
        }
    }

    /// Redact one object member, given the key it is stored under.
    ///
    /// The default ignores the key and redacts the value on its own merits.
    fn redact_value_for_key(&self, _key: &str, value: &mut serde_json::Value) {
        self.redact_json(value);
    }

    /// Redact an object key. Keys are usually field names — structure worth
    /// keeping — so the default returns them unchanged. A map keyed by user
    /// data is the exception, and the reason this hook exists.
    fn redact_key(&self, key: &str) -> String {
        key.to_owned()
    }
}

/// Redacting keys can make two of them collide (a map keyed by two different
/// addresses becomes two `[email]`s). Dropping the second would silently
/// discard forensic data, so it is suffixed instead.
fn insert_without_clobbering(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: String,
    value: serde_json::Value,
) {
    if !map.contains_key(&key) {
        map.insert(key, value);
        return;
    }
    for n in 2u32.. {
        let candidate = format!("{key}#{n}");
        if !map.contains_key(&candidate) {
            map.insert(candidate, value);
            return;
        }
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
    fn redact_json_preserves_key_order_and_membership() {
        let mut v = serde_json::json!({ "b": "2", "a": "1" });
        MaskDigits.redact_json(&mut v);
        assert_eq!(v["a"], "#");
        assert_eq!(v["b"], "#");
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    struct KeyCollider;
    impl Redactor for KeyCollider {
        fn redact(&self, input: &str) -> String {
            input.to_owned()
        }
        fn redact_key(&self, _key: &str) -> String {
            "same".to_owned()
        }
    }

    #[test]
    fn colliding_redacted_keys_are_suffixed_rather_than_dropped() {
        let mut v = serde_json::json!({ "a": 1, "b": 2, "c": 3 });
        KeyCollider.redact_json(&mut v);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 3, "no member may be silently discarded");
        assert!(obj.contains_key("same"));
        assert!(obj.contains_key("same#2"));
        assert!(obj.contains_key("same#3"));
    }
}

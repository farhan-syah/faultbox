// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redaction seam every adopting project may replace.

/// The marker substituted for a redacted value. Recognised on input too, so
/// redacting an already-redacted string is a no-op.
pub const REDACTED: &str = "[redacted]";

/// The marker substituted for something shaped like an email address.
pub const REDACTED_EMAIL: &str = "[email]";

/// The marker substituted for a subtree too deeply nested to walk.
pub const REDACTED_DEPTH: &str = "[redacted: nesting too deep]";

/// How deep [`Redactor::redact_json`] will descend before replacing the rest of
/// the subtree wholesale.
///
/// The walk is recursive, and it runs inside the panic hook over values the
/// adopter built — which may include JSON they parsed from a request. Without a
/// bound, a deeply nested payload overflows the stack *while a panic is being
/// reported*, turning a diagnosable failure into an unexplained abort and losing
/// the report that would have explained it.
///
/// Anything past this depth is masked rather than descended into, so the failure
/// direction stays the safe one: unwalkable means redacted, never emitted raw.
/// 64 is far past any real forensic payload — `serde_json`'s own parser stops
/// at 128 — so nothing legitimate reaches it.
pub const MAX_JSON_DEPTH: u32 = 64;

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
    /// Beyond [`MAX_JSON_DEPTH`] the remaining subtree is replaced with
    /// [`REDACTED_DEPTH`] instead of being descended into — see that constant
    /// for why a bound is required rather than merely tidy.
    fn redact_json(&self, value: &mut serde_json::Value) {
        let Some(_depth) = DepthGuard::enter() else {
            // Too deep to walk. Masking rather than leaving it alone keeps the
            // failure direction safe: what we could not inspect does not ship.
            *value = serde_json::Value::String(REDACTED_DEPTH.to_owned());
            return;
        };
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
                // Carried across the whole object so the suffix search never
                // rewinds — see `insert_without_clobbering`.
                let mut next_suffix = 2u32;
                for (key, mut v) in std::mem::take(map) {
                    self.redact_value_for_key(&key, &mut v);
                    insert_without_clobbering(
                        &mut rebuilt,
                        self.redact_key(&key),
                        v,
                        &mut next_suffix,
                    );
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

thread_local! {
    /// How deep the current thread is inside a JSON walk.
    static JSON_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Counts one level of JSON nesting, releasing it on drop.
///
/// The count lives on the thread rather than in a parameter because the walk is
/// *re-entrant through the trait*: the default `redact_value_for_key` calls back
/// into `redact_json`, and an implementor — [`BasicRedactor`] included — may
/// override it and do the same. A depth argument would restart at zero on every
/// such hop, so the bound would never fire on exactly the input it exists to
/// stop. A thread-local counts every level however the hooks are composed.
struct DepthGuard;

impl DepthGuard {
    /// Take one level, or `None` if that would exceed [`MAX_JSON_DEPTH`].
    fn enter() -> Option<DepthGuard> {
        JSON_DEPTH.with(|depth| {
            if depth.get() >= MAX_JSON_DEPTH {
                return None;
            }
            depth.set(depth.get() + 1);
            Some(DepthGuard)
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        JSON_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Redacting keys can make two of them collide (a map keyed by two different
/// addresses becomes two `[email]`s). Dropping the second would silently
/// discard forensic data, so it is suffixed instead.
/// `next_suffix` is the caller's running counter for the object being rebuilt.
/// Restarting the search at `2` for every collision makes redacting a map whose
/// keys all collapse to one marker quadratic — an object keyed by ten thousand
/// addresses costs tens of millions of lookups, inside the panic hook, where the
/// work not done is the cheapest work there is. The counter never rewinds, so
/// each insert is a lookup or two; the membership test is still what decides, so
/// a literal `key#7` already in the map cannot be clobbered.
fn insert_without_clobbering(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: String,
    value: serde_json::Value,
    next_suffix: &mut u32,
) {
    if !map.contains_key(&key) {
        map.insert(key, value);
        return;
    }
    while *next_suffix < u32::MAX {
        let candidate = format!("{key}#{}", *next_suffix);
        *next_suffix += 1;
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

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Masking the value of a `key = value` pair whose key names a credential.
//!
//! Two questions decide whether a credential survives: *where does the key
//! start* and *where does the value end*. Both are answered from the text's own
//! shape rather than from a fixed byte set.
//!
//! The key is read **backwards** from the separator, through any whitespace and
//! quotes, so `token=`, `token = `, `"token":` and `Authorization :` are one
//! case rather than four.
//!
//! The value's extent follows its form: a quoted value runs to its closing
//! quote (a password may contain a space), a composite value — `Some("…")`,
//! `Credentials("…", "…")`, `["…", "…"]`, `Secret { inner: "…" }` — has *every*
//! leaf inside it masked while its structure is kept, a value introduced by an
//! HTTP auth scheme takes the scheme *and* the credential after it (`Bearer`
//! alone is not the secret), and anything else is a single token.
//!
//! That last rule is where a multi-word secret could still hide — `token: abc
//! def` masks only `abc`. It is nonetheless the right rule, because the
//! alternative is worse: extending an unquoted value to the next delimiter
//! turns `authorization: header missing` and `password: incorrect for user 828`
//! into a bare `[redacted]`, destroying the message a report exists to carry,
//! and it cannot tell prose from a credential because nothing in the text says
//! which is which. A value that contains whitespace and is neither quoted nor
//! scheme-introduced is not reliably delimited for *any* reader. What actually
//! covers the gap is [`super::credentials`], which recognises credential
//! material wherever it appears, with or without a key in front of it.

use super::edit::Edit;
use super::keys::{KeyKind, classify};
use super::redactor::REDACTED;
use super::values::is_credential_shaped;
use std::borrow::Cow;

/// HTTP authentication schemes. The credential is the word *after* these, and
/// the scheme itself is part of the value being replaced.
const AUTH_SCHEMES: &[&str] = &[
    "bearer",
    "basic",
    "digest",
    "negotiate",
    "ntlm",
    "token",
    "apikey",
    "hoba",
    "mutual",
    "oauth",
    "sso",
];

pub(super) fn mask(input: &str) -> Cow<'_, str> {
    let bytes = input.as_bytes();
    let mut edit = Edit::new(input);
    let mut i = 0;

    while i < bytes.len() {
        if (bytes[i] == b'=' || bytes[i] == b':')
            && let Some(kind) = key_kind_ending_at(input, i)
        {
            i = mask_value(input, i + 1, kind, &mut edit);
            continue;
        }
        // Step over one whole UTF-8 character.
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
    }
    edit.finish()
}

/// Read the key that ends at `sep`, tolerating whitespace and quotes around it.
/// Returns `None` when the name does not promise a credential — including for
/// the `:` in `https://`, whose "key" reads back as `https`.
fn key_kind_ending_at(input: &str, sep: usize) -> Option<KeyKind> {
    let b = input.as_bytes();
    let mut end = sep;
    while end > 0 && (b[end - 1] == b' ' || b[end - 1] == b'\t') {
        end -= 1;
    }
    let quote = (end > 0 && (b[end - 1] == b'"' || b[end - 1] == b'\'')).then(|| b[end - 1]);
    if quote.is_some() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_byte(b[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    // A quoted key must actually be quoted on both sides; `a"b:` is not a key.
    if let Some(q) = quote
        && (start == 0 || b[start - 1] != q)
    {
        return None;
    }
    match classify(&input[start..end]) {
        KeyKind::Plain => None,
        kind => Some(kind),
    }
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// Mask the value starting at `i`, and return the index the main scan resumes
/// from. Everything not recorded as a masked span is untouched input, and stays
/// that way.
fn mask_value(input: &str, mut i: usize, kind: KeyKind, edit: &mut Edit) -> usize {
    let b = input.as_bytes();

    // Whitespace between the separator and the value is layout, not value.
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    if i >= b.len() {
        return i;
    }
    // Already redacted — by this redactor on an earlier pass, or by the
    // adopter's own before the string reached us. Step over the marker rather
    // than treating it as a fresh value and emitting `[redacted]]`.
    if input[i..].starts_with(REDACTED) {
        return i + REDACTED.len();
    }
    if b[i] == b'"' || b[i] == b'\'' {
        let (content_end, after) = quoted_extent(input, i);
        return if mask_leaf(input, i + 1, content_end, kind, edit) {
            after
        } else {
            i + 1
        };
    }
    // A composite value — `Some("…")`, `Credentials("…", "…")`, `["…", "…"]`,
    // `Secret { inner: "…" }` — hides its payload behind structure, and behind
    // *more than one* piece of it. Masking the first leaf and stopping is how a
    // `[redacted]` marker ends up printed next to the surviving secret.
    //
    // Only for a strong key: under a weak one the group is handed back to the
    // main scan instead, so an inner `password:` is judged on its own name
    // rather than on the outer key's.
    if kind == KeyKind::Strong
        && let Some(open) = group_open(input, i)
    {
        return mask_group(input, open, kind, edit);
    }

    let end = scheme_span(input, i).unwrap_or_else(|| token_end(input, i));
    if mask_leaf(input, i, end, kind, edit) {
        end
    } else {
        // Left as it stands — and *not* skipped over, because a value that
        // stays readable may itself contain the next assignment. Handing the
        // span back to the main scan is what makes redaction idempotent:
        // whether an inner `key=value` is seen must not depend on what
        // preceded it.
        i
    }
}

/// Mask every leaf inside the balanced group opening at `open`, keeping the
/// structure — brackets, field names, wrapper names, punctuation — intact.
/// Returns the index just past the matching close.
///
/// Iterative, with a depth counter rather than recursion: redaction runs inside
/// the panic hook, where a stack overflow on adversarially nested input would
/// be a second, worse failure than the one being reported.
fn mask_group(input: &str, open: usize, kind: KeyKind, edit: &mut Edit) -> usize {
    let b = input.as_bytes();
    let mut i = open + 1;
    let mut depth = 1u32;

    while i < b.len() {
        // A marker from an earlier pass is structure now, not a value: reading
        // its brackets as a nested group would nest it again on every pass.
        if input[i..].starts_with(REDACTED) {
            i += REDACTED.len();
            continue;
        }
        match b[i] {
            b'"' | b'\'' => {
                let (content_end, after) = quoted_extent(input, i);
                mask_leaf(input, i + 1, content_end, kind, edit);
                i = after;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            c if is_leaf_byte(c) => {
                let start = i;
                while i < b.len() && is_leaf_byte(b[i]) {
                    i += 1;
                }
                // A field name or a wrapper name introduces a value; it is not
                // one.
                if !introduces_a_value(input, i) {
                    mask_leaf(input, start, i, kind, edit);
                }
            }
            _ => {
                i += 1;
                while i < b.len() && (b[i] & 0xC0) == 0x80 {
                    i += 1;
                }
            }
        }
    }
    i
}

/// Where a composite value opens, if it does: a bracket, or a type name
/// followed by one — `Some(`, `Credentials(`, `Secret {`.
fn group_open(input: &str, i: usize) -> Option<usize> {
    let b = input.as_bytes();
    if matches!(b[i], b'(' | b'[' | b'{') {
        return Some(i);
    }
    if !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
        return None;
    }
    let mut j = i;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    if j < b.len() && matches!(b[j], b'(' | b'[') {
        return Some(j);
    }
    // `Name { … }` — the one form that spaces its bracket out.
    let mut k = j;
    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
        k += 1;
    }
    (k > j && k < b.len() && b[k] == b'{').then_some(k)
}

/// Does the token ending at `at` name something that follows, rather than being
/// a value itself?
fn introduces_a_value(input: &str, at: usize) -> bool {
    let b = input.as_bytes();
    let mut j = at;
    while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
        j += 1;
    }
    j < b.len() && matches!(b[j], b':' | b'(' | b'{')
}

fn is_leaf_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b'~' | b'@')
}

/// The content and the far side of a quoted run starting at `quote_at`.
fn quoted_extent(input: &str, quote_at: usize) -> (usize, usize) {
    let b = input.as_bytes();
    let quote = b[quote_at];
    let mut j = quote_at + 1;
    while j < b.len() && b[j] != quote {
        // A `Debug`-escaped quote is content, not the end of the value.
        j += if b[j] == b'\\' && j + 1 < b.len() {
            2
        } else {
            1
        };
    }
    let end = j.min(b.len());
    (end, if end < b.len() { end + 1 } else { end })
}

/// Record `input[start..end]` as masked, if it is a value this key masks.
fn mask_leaf(input: &str, start: usize, end: usize, kind: KeyKind, edit: &mut Edit) -> bool {
    let value = &input[start..end];
    if value == REDACTED || !masks(value, kind) {
        return false;
    }
    edit.replace(start, end, REDACTED);
    true
}

/// If the value opens with an HTTP auth scheme, the value is the scheme plus
/// the credential that follows it — and nothing after that, so the prose in
/// `authorization: Bearer <token> rejected` survives.
fn scheme_span(input: &str, i: usize) -> Option<usize> {
    let b = input.as_bytes();
    let mut word_end = i;
    while word_end < b.len() && (b[word_end].is_ascii_alphanumeric() || b[word_end] == b'-') {
        word_end += 1;
    }
    let word = &input[i..word_end];
    if !AUTH_SCHEMES.iter().any(|s| word.eq_ignore_ascii_case(s)) {
        return None;
    }
    let mut j = word_end;
    while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
        j += 1;
    }
    if j == word_end || j >= b.len() {
        return None;
    }
    // Exactly one token: the scheme names what the *next* word is, and says
    // nothing about the prose after it.
    let credential_end = token_end(input, j);
    (credential_end > j).then_some(credential_end)
}

/// The end of a single unbroken token — whitespace or structure, whichever
/// comes first.
fn token_end(input: &str, i: usize) -> usize {
    let b = input.as_bytes();
    let mut j = i;
    while j < b.len() && !is_structural(b[j]) && b[j] != b' ' && b[j] != b'\t' {
        j += 1;
    }
    j
}

/// Bytes that close the value's enclosing structure.
///
/// Quotes are absent on purpose. A value that is *delimited* by quotes never
/// reaches here — it is read by [`quoted_span`] from its opening quote. A quote
/// met part-way through an unquoted value is therefore content, and treating it
/// as an end is exactly how `secret=don't-tell-anyone` leaks its tail.
fn is_structural(b: u8) -> bool {
    matches!(b, b',' | b';' | b'&' | b'}' | b')' | b']' | b'\n' | b'\r')
}

/// A strong key masks whatever it holds; a weak one masks only what looks like
/// a credential, so `grouping_key=kind=0x09` stays readable.
fn masks(value: &str, kind: KeyKind) -> bool {
    !value.is_empty() && (kind != KeyKind::Weak || is_credential_shaped(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_read_through_quotes_and_spacing() {
        assert_eq!(mask(r#"{"api_key":"x"}"#), r#"{"api_key":"[redacted]"}"#);
        assert_eq!(mask("token = x"), "token = [redacted]");
        assert_eq!(mask("Authorization : x"), "Authorization : [redacted]");
    }

    #[test]
    fn a_url_scheme_is_not_a_key() {
        assert_eq!(
            mask("see https://example.com/x"),
            "see https://example.com/x"
        );
    }

    #[test]
    fn an_empty_value_stays_empty() {
        assert_eq!(mask("token="), "token=");
        assert_eq!(mask(r#"token="""#), r#"token="""#);
        assert_eq!(mask("token=, port=1"), "token=, port=1");
    }

    #[test]
    fn deeply_wrapped_values_are_still_reached_without_recursing() {
        let deep = format!("token: {}\"x\"{}", "S(".repeat(4096), ")".repeat(4096));
        let out = mask(&deep);
        assert!(
            !out.contains("\"x\""),
            "the payload must not survive nesting"
        );
    }

    #[test]
    fn multibyte_text_is_copied_through_intact() {
        assert_eq!(mask("café → token=abc"), "café → token=[redacted]");
        assert_eq!(mask("página=1"), "página=1");
    }
}

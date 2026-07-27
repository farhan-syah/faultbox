// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deciding whether a key name promises a credential.
//!
//! Key names arrive in every convention at once — `api_key`, `apiKey`,
//! `x-api-key`, `"api_key"`, `AZURE_OPENAI_KEY`, `http.authorization` — so the
//! name is normalised into segments and matched by *suffix*. `AZURE_OPENAI_KEY`
//! names a credential for the same reason `api_key` does: the thing it ends in.
//!
//! Suffix matching alone would then swallow ordinary diagnostic fields, since
//! `grouping_key`, `sort_key` and `partition_key` end the same way — and
//! `grouping_key` is the field a report is *fingerprinted* by. Hence two tiers:
//! a name that means "credential" on its own masks unconditionally, while a
//! name that is merely credential-adjacent masks only a value that is itself
//! shaped like a credential.

/// How strongly a key name predicts that its value is a credential.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum KeyKind {
    /// The name means "credential" on its own. Mask whatever follows.
    Strong,
    /// The name also occurs on ordinary diagnostic fields. Mask only a
    /// credential-shaped value.
    Weak,
    /// Not a credential name.
    Plain,
}

/// Segment sequences that name a credential outright, matched against the end
/// of a key's segments.
const STRONG: &[&[&str]] = &[
    &["password"],
    &["passwd"],
    &["passphrase"],
    &["secret"],
    &["token"],
    &["authorization"],
    &["bearer"],
    &["credential"],
    &["credentials"],
    &["cookie"],
    &["apikey"],
    &["api", "key"],
    &["access", "key"],
    &["secret", "key"],
    &["private", "key"],
    &["signing", "key"],
    &["encryption", "key"],
    &["client", "secret"],
    &["access", "token"],
    &["refresh", "token"],
    &["session", "token"],
    &["id", "token"],
    &["auth", "token"],
];

/// Segment sequences that *may* name a credential. `AZURE_OPENAI_KEY` and
/// `grouping_key` are indistinguishable by name alone; only the value tells
/// them apart.
const WEAK: &[&[&str]] = &[&["key"], &["auth"], &["session"], &["signature"]];

/// The longest pattern above, and therefore all of a key's tail that can ever
/// decide the answer.
const LONGEST_PATTERN: usize = 2;

/// Classify a key name, which may still carry its quotes and surrounding
/// whitespace.
///
/// Allocation-free: this runs once per `=` or `:` in every string entering a
/// report, including from inside the panic hook, where the cheapest work is the
/// work not done.
pub(super) fn classify(key: &str) -> KeyKind {
    let mut tail: [&str; LONGEST_PATTERN] = [""; LONGEST_PATTERN];
    let mut count = 0;

    for_each_segment(key, |segment| {
        if count < LONGEST_PATTERN {
            tail[count] = segment;
        } else {
            tail.rotate_left(1);
            tail[LONGEST_PATTERN - 1] = segment;
        }
        count += 1;
    });

    let tail = &tail[..count.min(LONGEST_PATTERN)];
    if tail.is_empty() {
        return KeyKind::Plain;
    }
    if matches_suffix(tail, STRONG) {
        KeyKind::Strong
    } else if matches_suffix(tail, WEAK) {
        KeyKind::Weak
    } else {
        KeyKind::Plain
    }
}

fn matches_suffix(tail: &[&str], table: &[&[&str]]) -> bool {
    table.iter().any(|pattern| {
        tail.len() >= pattern.len()
            && tail[tail.len() - pattern.len()..]
                .iter()
                .zip(pattern.iter())
                .all(|(seg, want)| seg.eq_ignore_ascii_case(want))
    })
}

/// Split a key into word segments, across every convention at once: `_`, `-`,
/// `.`, whitespace and camelCase boundaries all separate, and quotes are not
/// part of the name. Segments are borrowed and compared case-insensitively, so
/// nothing is copied or lowercased.
fn for_each_segment<'a>(key: &'a str, mut emit: impl FnMut(&'a str)) {
    let mut start = None;
    let mut prev_lower = false;

    for (at, c) in key.char_indices() {
        if !c.is_ascii_alphanumeric() {
            if let Some(from) = start.take() {
                emit(&key[from..at]);
            }
            prev_lower = false;
            continue;
        }
        match start {
            // `apiKey` and `APIKey` both break before the final word.
            Some(from) if c.is_ascii_uppercase() && prev_lower => {
                emit(&key[from..at]);
                start = Some(at);
            }
            Some(_) => {}
            None => start = Some(at),
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    if let Some(from) = start {
        emit(&key[from..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_naming_convention_reaches_the_same_classification() {
        for key in [
            "api_key",
            "apiKey",
            "API_KEY",
            "x-api-key",
            "\"api_key\"",
            "http.api.key",
            " api_key ",
        ] {
            assert_eq!(classify(key), KeyKind::Strong, "{key}");
        }
    }

    #[test]
    fn credential_names_are_matched_by_suffix() {
        assert_eq!(classify("proxy-authorization"), KeyKind::Strong);
        assert_eq!(classify("stripe_secret_key"), KeyKind::Strong);
        assert_eq!(classify("set-cookie"), KeyKind::Strong);
        assert_eq!(classify("github_access_token"), KeyKind::Strong);
    }

    #[test]
    fn ambiguous_names_are_weak_rather_than_strong() {
        // Masking these unconditionally would eat the field a report is
        // fingerprinted by.
        assert_eq!(classify("grouping_key"), KeyKind::Weak);
        assert_eq!(classify("AZURE_OPENAI_KEY"), KeyKind::Weak);
        assert_eq!(classify("auth"), KeyKind::Weak);
    }

    #[test]
    fn non_ascii_keys_are_segmented_without_panicking() {
        // JSON object keys are arbitrary text, and this runs on all of them.
        assert_eq!(classify("página_id"), KeyKind::Plain);
        assert_eq!(classify("日本語_token"), KeyKind::Strong);
        assert_eq!(classify("→"), KeyKind::Plain);
    }

    #[test]
    fn ordinary_diagnostic_names_are_plain() {
        assert_eq!(classify("page_id"), KeyKind::Plain);
        assert_eq!(classify("broken_tokens"), KeyKind::Plain);
        assert_eq!(classify("https"), KeyKind::Plain);
        assert_eq!(classify(""), KeyKind::Plain);
        assert_eq!(classify("   "), KeyKind::Plain);
    }
}

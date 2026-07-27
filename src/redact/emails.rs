// SPDX-License-Identifier: MIT OR Apache-2.0

//! Masking anything shaped like an email address.
//!
//! Addresses arrive punctuated: comma-joined in a recipient list, angle-bracket
//! wrapped in a header, tab-aligned in a table, at the start of a line in an
//! error chain. Splitting on the space character alone therefore does two
//! things wrong at once — it treats `a@x.com,b@x.com` as one malformed address
//! and lets both through, and it treats a whole tab- or newline-separated
//! segment as one address and replaces all of it, destroying the diagnostic the
//! report exists to carry.
//!
//! So the scan accumulates only the characters an address can be made of, and
//! copies every delimiter through untouched.

use super::edit::Edit;
use super::redactor::REDACTED_EMAIL;
use std::borrow::Cow;

pub(super) fn mask(input: &str) -> Cow<'_, str> {
    if !input.contains('@') {
        return Cow::Borrowed(input);
    }
    let mut edit = Edit::new(input);
    let mut candidate_start = None;

    for (idx, ch) in input.char_indices() {
        if is_address_char(ch) {
            candidate_start.get_or_insert(idx);
            continue;
        }
        if let Some(start) = candidate_start.take()
            && looks_like_email(&input[start..idx])
        {
            edit.replace(start, idx, REDACTED_EMAIL);
        }
    }
    if let Some(start) = candidate_start
        && looks_like_email(&input[start..])
    {
        edit.replace(start, input.len(), REDACTED_EMAIL);
    }
    edit.finish()
}

/// The characters RFC-shaped addresses are made of in practice. Deliberately
/// narrow: everything excluded here is a delimiter that survives redaction.
fn is_address_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+' | '%')
}

fn looks_like_email(candidate: &str) -> bool {
    let Some((local, domain)) = candidate.split_once('@') else {
        return false;
    };
    let trimmed_local = local.trim_matches('.');
    !trimmed_local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_address_in_a_punctuated_list_is_masked() {
        assert_eq!(
            mask("to ada@example.com,grace@example.com;<hopper@example.com>"),
            "to [email],[email];<[email]>"
        );
    }

    #[test]
    fn delimiters_other_than_a_space_survive() {
        assert_eq!(
            mask("caused by:\nada@example.com lost it"),
            "caused by:\n[email] lost it"
        );
        assert_eq!(mask("a\tada@example.com\tb"), "a\t[email]\tb");
    }

    #[test]
    fn near_misses_are_left_alone() {
        for input in [
            "user@localhost",
            "@example.com",
            "ada@.com",
            "ada@example.",
            "ada@example.c",
            "no address here",
            "8@9.0",
        ] {
            assert_eq!(mask(input), input, "{input}");
        }
    }

    #[test]
    fn multibyte_text_survives_the_scan() {
        assert_eq!(mask("café ada@example.com →"), "café [email] →");
    }
}

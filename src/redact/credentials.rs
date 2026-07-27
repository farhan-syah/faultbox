// SPDX-License-Identifier: MIT OR Apache-2.0

//! Masking a credential that arrives with no key in front of it.
//!
//! Key-driven masking only fires when someone wrote the key down. Real messages
//! do not cooperate: a retry log says `retrying with sk-live-…`, a stack trace
//! carries a JWT inside a URL, a config dump embeds a PEM block. Those are the
//! same leak, one shape further out.
//!
//! Recognition is by issuer evidence only — a documented vendor prefix, a JWT's
//! three-segment structure, a PEM header — never by entropy, because a report
//! is full of build-ids and hashes that an entropy score would destroy.

use super::edit::{Edit, chain};
use super::redactor::REDACTED;
use super::values::{is_jwt, issuer_prefix_start};
use std::borrow::Cow;

/// PEM bodies span lines, so they are handled before tokenising.
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";

pub(super) fn mask_standalone(input: &str) -> Cow<'_, str> {
    chain(mask_pem_blocks(input), mask_tokens)
}

fn mask_tokens(input: &str) -> Cow<'_, str> {
    let mut edit = Edit::new(input);
    let mut token_start = None;

    for (idx, ch) in input.char_indices() {
        if is_token_char(ch) {
            token_start.get_or_insert(idx);
            continue;
        }
        if let Some(start) = token_start.take() {
            mask_token(&input[start..idx], start, &mut edit);
        }
    }
    if let Some(start) = token_start {
        mask_token(&input[start..], start, &mut edit);
    }
    edit.finish()
}

/// Characters that may appear inside a candidate credential. Everything else —
/// including `/` and `=`, which end a URL path segment and a query parameter —
/// separates one candidate from the next, so a token embedded in a URL is still
/// seen on its own.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+')
}

fn mask_token(token: &str, at: usize, edit: &mut Edit) {
    if is_jwt(token) {
        edit.replace(at, at + token.len(), REDACTED);
        return;
    }
    // Whatever punctuated the credential onto the text before it is not part
    // of the credential, and may itself be diagnostic.
    if let Some(offset) = issuer_prefix_start(token) {
        edit.replace(at + offset, at + token.len(), REDACTED);
    }
}

/// Replace the body of every `-----BEGIN … KEY-----` block. The markers stay:
/// *that* a key was in the message is diagnostic, its bytes are not.
fn mask_pem_blocks(input: &str) -> Cow<'_, str> {
    if !input.contains(PEM_BEGIN) {
        return Cow::Borrowed(input);
    }
    let mut edit = Edit::new(input);
    let mut at = 0;

    while let Some(begin) = input[at..].find(PEM_BEGIN) {
        let after_begin = at + begin + PEM_BEGIN.len();
        let Some(header_end) = input[after_begin..].find("-----") else {
            break;
        };
        let body_start = after_begin + header_end + "-----".len();
        // An unterminated block is still a leak, so it is masked to the end.
        let body_end = input[body_start..]
            .find(PEM_END)
            .map_or(input.len(), |e| body_start + e);

        if body_end > body_start {
            edit.replace(body_start, body_end, REDACTED);
        }
        at = body_end;
    }
    edit.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_prefixed_tokens_are_masked_without_a_key() {
        assert_eq!(
            mask_standalone("retrying with sk-live-4242deadbeef4242 after 401"),
            "retrying with [redacted] after 401"
        );
        assert_eq!(
            mask_standalone("(ghp_abcdefghijklmnopqrstuvwxyz0123456789)"),
            "([redacted])"
        );
    }

    #[test]
    fn jwts_are_masked_wherever_they_appear() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
        let line = format!("GET /v1/x?t={jwt} -> 401");
        let out = mask_standalone(&line);
        assert!(!out.contains(jwt), "{out}");
    }

    #[test]
    fn ordinary_diagnostics_are_left_alone() {
        for input in [
            "build_id=9f8e7d6c5b4a39281706",
            "thread 'main' panicked at src/lib.rs:42",
            "page 828 checksum mismatch",
            "[redacted]",
        ] {
            assert_eq!(mask_standalone(input), input, "{input}");
        }
    }

    #[test]
    fn pem_bodies_are_masked_and_the_markers_kept() {
        let pem = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK\nCAQEA\n-----END RSA PRIVATE KEY-----\ndone";
        let out = mask_standalone(pem);
        assert!(!out.contains("MIIEpQIBAAK"), "{out}");
        assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"), "{out}");
        assert!(out.contains("-----END RSA PRIVATE KEY-----"), "{out}");
        assert!(out.ends_with("done"), "{out}");
    }

    #[test]
    fn an_unterminated_pem_block_is_masked_to_the_end() {
        let out = mask_standalone("-----BEGIN PRIVATE KEY-----\nMIIEpQIBAAKCAQEA");
        assert!(!out.contains("MIIEpQIBAAKCAQEA"), "{out}");
    }
}

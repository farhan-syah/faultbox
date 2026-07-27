// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recognising a credential by the shape of the value itself.
//!
//! This is what makes suffix-matched key names safe: `AZURE_OPENAI_KEY` and
//! `grouping_key` are the same name to a segment matcher, but
//! `sk-azure-abcdef123456` and `kind=0x09` are not the same value. It is also
//! what finds a credential that arrives with no key at all — pasted into a log
//! line, embedded in a URL, echoed inside a stack trace.
//!
//! Only *issuer-shaped* evidence counts: a documented vendor prefix, a JWT, or
//! a long opaque alphanumeric run. Deliberately **not** an entropy score — a
//! report is full of build-ids, hashes and UUIDs that any entropy heuristic
//! would eat, and those are the identifiers that make a report symbolicatable.

/// Prefixes that vendors have committed to as credential markers. A token that
/// starts with one is a credential regardless of the key it sits under.
const ISSUER_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "shpat_",
    "shpss_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "gldt-",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "npm_",
    "dop_v1_",
    "doo_v1_",
    "hf_",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
];

/// The shortest opaque run that is credential-like on its own. Short enough to
/// catch a 16-character API key, long enough that ordinary identifiers, error
/// codes and version strings fall below it.
const OPAQUE_MIN_LEN: usize = 16;

/// Is this value, on its own evidence, a credential?
pub(super) fn is_credential_shaped(value: &str) -> bool {
    let value = value.trim().trim_matches(['"', '\'']);
    if value.is_empty() || value == super::REDACTED {
        return false;
    }
    if has_issuer_prefix(value) || is_jwt(value) {
        return true;
    }
    is_opaque_run(value)
}

/// A vendor-marked token: the prefix, plus enough after it to be a secret
/// rather than a word that happens to start the same way.
pub(super) fn has_issuer_prefix(value: &str) -> bool {
    ISSUER_PREFIXES.iter().any(|prefix| {
        value.len() >= prefix.len() + 8
            && value.starts_with(prefix)
            && value[prefix.len()..].bytes().all(is_token_byte)
    })
}

/// Where a vendor-marked credential starts inside `token`, if anywhere.
///
/// A credential is often punctuated onto what precedes it — `-sk-live-…` in a
/// command line, `foo.ghp_…` in a path. The match must not begin mid-word,
/// though: `my-task-manager` contains `sk-`, and masking on that basis would
/// shred ordinary identifiers for nothing.
pub(super) fn issuer_prefix_start(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    ISSUER_PREFIXES
        .iter()
        .filter_map(|prefix| {
            token.match_indices(prefix).find_map(|(at, _)| {
                let starts_a_word = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
                (starts_a_word && has_issuer_prefix(&token[at..])).then_some(at)
            })
        })
        .min()
}

/// Three base64url segments, the first of which is a JSON header — `{"alg"` and
/// `{"typ"` both base64-encode to a leading `eyJ`.
pub(super) fn is_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    header.starts_with("eyJ")
        && [header, payload, signature]
            .iter()
            .all(|p| p.len() >= 8 && p.bytes().all(is_base64url_byte))
}

/// A long unbroken run of opaque token material with both letters and digits —
/// what a key generator emits and what a human-readable diagnostic value is
/// not.
fn is_opaque_run(value: &str) -> bool {
    value.len() >= OPAQUE_MIN_LEN
        && value.bytes().all(is_token_byte)
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value.bytes().any(|b| b.is_ascii_digit())
}

/// Bytes that may appear inside opaque credential material: the alphanumerics
/// plus the separators base64url, hex-dashed and vendor formats use.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b'~')
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_prefixed_tokens_are_credentials() {
        assert!(is_credential_shaped("sk-azure-abcdef123456"));
        assert!(is_credential_shaped(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        ));
        assert!(is_credential_shaped("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_credential_shaped("\"sk-live-4242deadbeef\""));
    }

    #[test]
    fn jwts_are_credentials() {
        assert!(is_credential_shaped(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g"
        ));
        assert!(!is_jwt("a.b.c"));
        assert!(!is_jwt("not.a.jwt.at.all"));
    }

    #[test]
    fn diagnostic_values_are_not_credentials() {
        // The fields a report is read by must survive a weak key name.
        assert!(!is_credential_shaped("kind=0x09"));
        assert!(!is_credential_shaped("page_id"));
        assert!(!is_credential_shaped("7"));
        assert!(!is_credential_shaped("none"));
        assert!(!is_credential_shaped("oauth2"));
        assert!(!is_credential_shaped("a long human sentence"));
        assert!(!is_credential_shaped(""));
        assert!(!is_credential_shaped(super::super::REDACTED));
    }

    #[test]
    fn opaque_runs_need_both_letters_and_digits_and_length() {
        assert!(is_credential_shaped("A1b2C3d4E5f6G7h8"));
        // A 16-character all-alphabetic word is prose, not a key.
        assert!(!is_credential_shaped("abcdefghijklmnop"));
        // Below the length floor, even mixed material is an identifier.
        assert!(!is_credential_shaped("a1b2c3d4"));
    }
}

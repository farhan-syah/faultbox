// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redaction contract `BasicRedactor` owes its adopters.
//!
//! `BasicRedactor` is the default a project reaches for when it wants reports
//! that are safe to bundle and submit, so its failure mode matters more than
//! its precision: leaving a diagnostic field masked costs a debugging session,
//! leaving a live credential unmasked ships it to whoever receives the report.
//!
//! These tests pin the shapes credentials actually arrive in — HTTP header
//! lines, JSON bodies echoed by a client's error string, `Debug` output of a
//! config struct, TOML-ish key/value dumps, environment variables, structured
//! breadcrumb fields — rather than the single `key=value` shape that is easy to
//! scan for. Each case asserts both the redacted rendering *and*, where a
//! credential is involved, that no fragment of the secret survives anywhere in
//! the output: the failure being guarded against is a silent partial mask, and
//! an equality assertion alone tends to be rewritten to match whatever the
//! implementation happens to emit.

use faultbox::{BasicRedactor, Redactor};

/// A redactor with a home directory that cannot match anything on the test
/// machine, so these cases exercise credential handling alone.
fn redactor() -> BasicRedactor {
    BasicRedactor::new().home("/nonexistent-home-for-tests")
}

/// The load-bearing assertion: the secret is *gone*, not merely shortened.
fn assert_no_trace(output: &str, secret: &str) {
    assert!(
        !output.contains(secret),
        "redacted output still carries the credential\n  secret: {secret}\n  output: {output}"
    );
}

#[test]
fn authorization_header_credentials_are_masked_past_the_scheme() {
    let r = redactor();

    // The shape an HTTP client's error string echoes. The credential follows a
    // scheme word, so a value that ends at the first space ends on `Bearer`.
    let out = r.redact("request failed: authorization: Bearer sk-live-4242deadbeef4242 rejected");
    assert_no_trace(&out, "sk-live-4242deadbeef4242");
    assert_eq!(
        out, "request failed: authorization: [redacted] rejected",
        "the scheme and its credential are one value; the surrounding prose stays readable"
    );

    let out = r.redact("authorization: Basic YWRhOmh1bnRlcjI=");
    assert_no_trace(&out, "YWRhOmh1bnRlcjI=");
}

#[test]
fn quoted_values_are_masked_to_the_closing_quote() {
    let r = redactor();

    // `Debug` output of a config whose secret contains a space.
    let out = r.redact(r#"Config { password: "hunter 2", port: 5432 }"#);
    assert_no_trace(&out, "hunter 2");
    assert_no_trace(&out, " 2");
    assert_eq!(
        out, r#"Config { password: "[redacted]", port: 5432 }"#,
        "the quotes delimit the value; the diagnostic field after it survives"
    );

    let out = r.redact("secret = 'multi word value'");
    assert_no_trace(&out, "multi word value");
    assert_no_trace(&out, "word value");
}

#[test]
fn a_quote_inside_an_unquoted_value_is_content_not_the_end_of_it() {
    let r = redactor();

    // The same failure one byte further down: a value that is not *delimited*
    // by quotes may still contain one, and ending it there leaks the tail.
    let out = r.redact("secret=don't-tell-anyone");
    assert_no_trace(&out, "t-tell-anyone");
    assert_eq!(out, "secret=[redacted]");
}

#[test]
fn quoted_keys_are_recognised() {
    let r = redactor();

    // A JSON body or header map rendered into an error string: the key is
    // quoted, so it no longer ends immediately before the separator.
    let out = r.redact(r#"{"api_key":"sk-plain-1234"}"#);
    assert_no_trace(&out, "sk-plain-1234");
    assert_eq!(out, r#"{"api_key":"[redacted]"}"#);

    let out = r.redact(r#"upstream said: {"authorization": "Bearer sk-live-9999"}"#);
    assert_no_trace(&out, "sk-live-9999");
}

#[test]
fn whitespace_around_the_separator_does_not_defeat_matching() {
    let r = redactor();

    // TOML and most hand-written config dumps space the separator out.
    let out = r.redact(r#"token = "sk-toml-1234""#);
    assert_no_trace(&out, "sk-toml-1234");
    assert_eq!(out, r#"token = "[redacted]""#);

    let out = r.redact("Authorization : Bearer sk-spaced-1234");
    assert_no_trace(&out, "sk-spaced-1234");
}

#[test]
fn wrapped_values_are_masked_inside_the_wrapper() {
    let r = redactor();

    // `Debug` of an `Option<String>` field — the wrapper's `(` and `"` sit
    // between the separator and the credential.
    let out = r.redact(r#"Config { token: Some("sk-opt-1234"), retries: 3 }"#);
    assert_no_trace(&out, "sk-opt-1234");
    assert_eq!(
        out, r#"Config { token: Some("[redacted]"), retries: 3 }"#,
        "the wrapper is structure worth keeping; only its payload is a secret"
    );
}

#[test]
fn hyphenated_header_keys_are_recognised() {
    let r = redactor();

    let out = r.redact("x-api-key: sk-header-1234");
    assert_no_trace(&out, "sk-header-1234");
    assert_eq!(out, "x-api-key: [redacted]");

    let out = r.redact("proxy-authorization: Bearer sk-proxy-1234");
    assert_no_trace(&out, "sk-proxy-1234");
}

#[test]
fn credential_bearing_key_suffixes_are_recognised() {
    let r = redactor();

    // Vendor environment variables name the credential by suffix, never by the
    // exact word a fixed key list happens to contain.
    let out = r.redact("AZURE_OPENAI_KEY=sk-azure-abcdef123456");
    assert_no_trace(&out, "sk-azure-abcdef123456");
    assert_eq!(out, "AZURE_OPENAI_KEY=[redacted]");

    let out = r.redact("GITHUB_ACCESS_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    assert_no_trace(&out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789");

    let out = r.redact("stripe_secret_key=sk_live_abcdefghijklmnop");
    assert_no_trace(&out, "sk_live_abcdefghijklmnop");
}

#[test]
fn structural_keys_that_merely_end_in_key_stay_readable() {
    let r = redactor();

    // The cost of matching suffixes is over-redaction of ordinary diagnostic
    // fields, which are the whole point of a report. A key that names a
    // position rather than a credential keeps its value: nothing about these
    // is credential-shaped.
    assert_eq!(r.redact("grouping_key=kind=0x09"), "grouping_key=kind=0x09");
    assert_eq!(r.redact("sort_key=page_id"), "sort_key=page_id");
    assert_eq!(r.redact("partition_key=7"), "partition_key=7");
}

#[test]
fn json_object_keys_naming_a_secret_are_masked() {
    let r = redactor();

    // Breadcrumb fields and `DomainContext` payloads reach the writer as JSON,
    // where the key lives in the object rather than in the string, so a
    // per-string scan for `key=value` never sees it.
    let mut v = serde_json::json!({
        "authorization": "Bearer sk-json-1234",
        "page_id": 828,
        "upstream": { "password": "hunter2" },
        "headers": [ { "x-api-key": "sk-array-1234" } ],
    });
    r.redact_json(&mut v);

    let rendered = v.to_string();
    assert_no_trace(&rendered, "sk-json-1234");
    assert_no_trace(&rendered, "hunter2");
    assert_no_trace(&rendered, "sk-array-1234");
    assert_eq!(v["page_id"], 828, "structural fields survive untouched");
}

#[test]
fn every_address_in_a_list_is_masked() {
    let r = redactor();

    // A comma-joined recipient list is one whitespace-delimited token, so
    // splitting on spaces alone sees a single malformed address and lets both
    // real ones through.
    let out = r.redact("owners ada@example.com,grace@example.com lost the write");
    assert_no_trace(&out, "ada@example.com");
    assert_no_trace(&out, "grace@example.com");
    assert_eq!(out, "owners [email],[email] lost the write");

    let out = r.redact("from <ada@example.com>; to <grace@example.com>");
    assert_no_trace(&out, "ada@example.com");
    assert_no_trace(&out, "grace@example.com");
}

#[test]
fn addresses_delimited_by_other_whitespace_do_not_swallow_the_line() {
    let r = redactor();

    // Error chains and `Debug` output are multi-line and tab-aligned. Treating
    // a space as the only separator makes the whole surrounding line part of
    // the address, and it is replaced wholesale — destroying the diagnostic
    // that the report exists to carry.
    assert_eq!(
        r.redact("caused by:\nada@example.com lost the write"),
        "caused by:\n[email] lost the write"
    );
    assert_eq!(
        r.redact("owner\tada@example.com\tstate=open"),
        "owner\t[email]\tstate=open"
    );
}

#[test]
fn url_query_secrets_end_at_the_parameter_boundary() {
    let r = redactor();

    // `&` separates query parameters, so a value that runs to the end of the
    // string swallows every remaining diagnostic after the credential.
    let out = r.redact("GET https://api.example.com/v1?api_key=sk-url-1234&page=3 -> 401");
    assert_no_trace(&out, "sk-url-1234");
    assert_eq!(
        out,
        "GET https://api.example.com/v1?api_key=[redacted]&page=3 -> 401"
    );
}

#[test]
fn plain_assignments_and_lookalike_keys_keep_their_existing_behaviour() {
    let r = redactor();

    // The shapes that already worked must keep working: a masked credential
    // must not start eating the diagnostic fields that follow it.
    assert_eq!(
        r.redact("connect failed token=sk-abc123 retries=3"),
        "connect failed token=[redacted] retries=3"
    );
    assert_eq!(r.redact("broken_tokens=4"), "broken_tokens=4");
    assert_eq!(r.redact("page_id=828"), "page_id=828");
    assert_eq!(r.redact("user@localhost"), "user@localhost");
}

/// An unquoted value is one token, and the message around it survives.
///
/// The alternative — running the value on to the next delimiter — masks a
/// multi-word secret, but it cannot tell a secret from prose, because nothing
/// in the text says which is which. It turns the messages below into a bare
/// `[redacted]`, destroying exactly what a report is for. A value carrying
/// whitespace that is neither quoted nor scheme-introduced is not reliably
/// delimited for any reader; quoting it or naming a scheme is what makes it
/// one, and both of those are covered. What closes the remaining gap is not a
/// wider value rule but keyless recognition: a credential that *looks* like
/// one is masked wherever it sits, as the last case here shows.
#[test]
fn an_unquoted_value_is_one_token_and_the_message_survives() {
    let r = redactor();

    assert_eq!(
        r.redact("authorization: header missing"),
        "authorization: [redacted] missing"
    );
    assert_eq!(
        r.redact("password: incorrect for user 828"),
        "password: [redacted] for user 828"
    );

    // The safety net: no key needed, so a real credential is caught even where
    // the value rule stops early.
    let out = r.redact("password: was sk-live-4242deadbeef4242 all along");
    assert_no_trace(&out, "sk-live-4242deadbeef4242");
    assert_eq!(out, "password: [redacted] [redacted] all along");
}

#[test]
fn credentials_are_masked_even_with_no_key_in_front_of_them() {
    let r = redactor();

    // A retry log, a stack trace, a URL — the key is simply not written down.
    let out = r.redact("retrying with sk-live-4242deadbeef4242 after 401");
    assert_no_trace(&out, "sk-live-4242deadbeef4242");
    assert_eq!(out, "retrying with [redacted] after 401");

    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJ";
    let out = r.redact(&format!("GET /v1/session?t={jwt} -> 401"));
    assert_no_trace(&out, jwt);

    let out = r
        .redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA\n-----END RSA PRIVATE KEY-----");
    assert_no_trace(&out, "MIIEpQIBAAKCAQEA");
    assert!(
        out.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "that a key was present is itself diagnostic: {out}"
    );
}

#[test]
fn identifiers_that_make_a_report_readable_are_not_mistaken_for_credentials() {
    let r = redactor();

    // The cost of hunting keyless credentials is eating the identifiers a
    // report is symbolicated and triaged by. Recognition is by issuer
    // evidence, never by entropy, precisely so these survive.
    for input in [
        "build_id=9f8e7d6c5b4a392817069f8e7d6c5b4a39281706",
        "fingerprint 5b1e0c9a4f2d8e7b6a3c1d0f9e8b7a6c",
        "at 0x00007f9c8b2a4e10 in libstore.so",
        "trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
    ] {
        assert_eq!(r.redact(input), input, "{input}");
    }
}

#[test]
fn credential_adjacent_keys_mask_on_the_value_not_the_name() {
    let r = redactor();

    // `auth` names a mode as often as it names a credential.
    assert_eq!(r.redact("auth: none, retries=3"), "auth: none, retries=3");
    assert_eq!(r.redact("auth_attempts=3"), "auth_attempts=3");

    let out = r.redact("auth=sk-live-4242deadbeef4242");
    assert_no_trace(&out, "sk-live-4242deadbeef4242");
}

#[test]
fn the_home_directory_survives_case_separator_and_boundary_differences() {
    let unix = BasicRedactor::new().home("/home/ada");
    assert_eq!(
        unix.redact("failed to open /home/ada/db/main.db"),
        "failed to open ~/db/main.db",
        "the path shape a maintainer needs survives; the username does not"
    );
    // A username that prefixes another one must not corrupt that other path.
    assert_eq!(
        BasicRedactor::new()
            .home("/home/ad")
            .redact("/home/adam/db"),
        "/home/adam/db"
    );
    // The username is identifying wherever it appears, not only under $HOME.
    assert_eq!(
        unix.redact("spilled to /var/log/ada/store.log"),
        "spilled to /var/log/~user/store.log"
    );

    // One directory, several spellings on one machine.
    let windows = BasicRedactor::new().home("C:\\Users\\Ada");
    assert_eq!(
        windows.redact("open c:/users/ada/db/main.db"),
        "open ~/db/main.db"
    );
    assert_eq!(windows.redact("open C:\\Users\\Ada\\db"), "open ~\\db");
}

#[test]
fn map_keys_made_of_user_data_are_masked() {
    let r = redactor();

    // A breadcrumb field keyed by the record it describes: the key is content,
    // and nothing about walking values would ever reach it.
    let mut v = serde_json::json!({
        "ada@example.com": { "writes": 3 },
        "grace@example.com": { "writes": 4 },
    });
    r.redact_json(&mut v);

    let rendered = v.to_string();
    assert_no_trace(&rendered, "ada@example.com");
    assert_no_trace(&rendered, "grace@example.com");
    assert_eq!(
        v.as_object().unwrap().len(),
        2,
        "colliding masked keys must not silently discard a member"
    );
}

/// Redaction runs inside the panic hook, so a slicing bug in it turns a
/// reportable panic into an abort with no report at all. Nothing about the
/// input is trustworthy at that point: it is whatever the failing program was
/// holding.
#[test]
fn redaction_never_panics_and_always_settles_on_arbitrary_input() {
    let r = redactor();

    // A deterministic generator over exactly the bytes that steer the scanners
    // — separators, quotes, wrappers, delimiters, multi-byte characters, and
    // the markers redaction itself emits — beats a random corpus that would
    // spend its budget on inert text.
    const ALPHABET: &[&str] = &[
        "=",
        ":",
        "\"",
        "'",
        " ",
        "\t",
        "\n",
        ",",
        ";",
        "&",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "/",
        "\\",
        "@",
        ".",
        "-",
        "_",
        "~",
        "token",
        "password",
        "authorization",
        "api_key",
        "grouping_key",
        "auth",
        "Bearer",
        "Some",
        "sk-live-4242deadbeef",
        "ada@example.com",
        "[redacted]",
        "[email]",
        "café",
        "→",
        "日本語",
        "0x09",
        "828",
        "\u{0}",
    ];

    // A linear congruential generator: deterministic, so a failure here is
    // reproducible from the seed alone.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };

    for _ in 0..20_000 {
        let mut input = String::new();
        for _ in 0..(next() % 24) {
            input.push_str(ALPHABET[next() % ALPHABET.len()]);
        }
        let once = r.redact(&input);
        assert_eq!(
            r.redact(&once),
            once,
            "redaction must reach a fixed point, or repeated passes corrupt \
             the report: {input:?}"
        );
        assert!(
            !starts_a_word(&once, CREDENTIAL),
            "a credential survived: {input:?} -> {once:?}"
        );
    }
}

/// The credential the generator plants, and the only one it must never leak.
const CREDENTIAL: &str = "sk-live-4242deadbeef";

/// Does the credential begin a word somewhere in `input`?
///
/// A credential glued directly onto preceding alphanumerics (`…0x09sk-live-…`)
/// is not recoverable: `my-task-manager` contains `sk-` too, and masking on that
/// basis would shred ordinary identifiers for no gain. Detection is therefore
/// anchored to word starts, and that is what the generator may legitimately
/// expect of it.
fn starts_a_word(input: &str, credential: &str) -> bool {
    input.match_indices(credential).any(|(at, _)| {
        at == 0
            || !input[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

#[test]
fn redacting_an_already_redacted_string_changes_nothing() {
    let r = redactor();

    // Crumbs are redacted on the way into the ring and again on the way into a
    // report, so every shape above passes through twice.
    for input in [
        "request failed: authorization: Bearer sk-live-4242deadbeef4242 rejected",
        r#"Config { password: "hunter 2", port: 5432 }"#,
        r#"{"api_key":"sk-plain-1234"}"#,
        r#"token = "sk-toml-1234""#,
        r#"Config { token: Some("sk-opt-1234"), retries: 3 }"#,
        "x-api-key: sk-header-1234",
        "AZURE_OPENAI_KEY=sk-azure-abcdef123456",
        "owners ada@example.com,grace@example.com lost the write",
        "GET https://api.example.com/v1?api_key=sk-url-1234&page=3 -> 401",
        "connect failed token=sk-abc123 retries=3",
    ] {
        let once = r.redact(input);
        assert_eq!(
            r.redact(&once),
            once,
            "re-redacting must not corrupt: {input}"
        );
    }
}

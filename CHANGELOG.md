# Changelog

All notable changes to `faultbox` will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
`faultbox` uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut from this file: the release workflow refuses a tag whose base version has no non-empty section here, and publishes that section as the GitHub release notes. Rename `[Unreleased]` to the version you are tagging before you push the tag.

<!-- Link definitions live above the first section: everything below a version heading is extracted verbatim into that release's notes. -->

[unreleased]: https://github.com/farhan-syah/faultbox/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/farhan-syah/faultbox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/farhan-syah/faultbox/releases/tag/v0.1.0

---

## [Unreleased]

A hardening release from an internal audit. Nothing is removed from the public API and no existing signature changes, so upgrading is a drop-in. `cargo deny check` reports no advisories anywhere in the dependency tree.

Two changes alter observable behaviour and are worth reading before you upgrade.

### Changed

- **Report directories and files are created owner-only on unix** — `0700` directories, `0600` files — rather than at the process umask, and a preserved artifact no longer inherits a permissive mode from its source. A group directory created by an earlier version is narrowed the next time it is written to. **If something other than the reporting user reads your reports directory — a support account, a log shipper — it will lose access.** Windows has no mode bits and this crate sets no explicit DACL, so there the directory stays exactly as private as the location you point it at.
- **Preserved-artifact names must be a single plain path component.** A name carrying a path separator, `..`, or one of the recorder's own file names is refused and recorded on the report as `NOT PRESERVED` instead of being acted on. Ordinary names (`store.corrupt`, `main.db`) are unaffected.
- **Artifact digests are SHA-256** instead of 64-bit FNV-1a, so a digest recorded by an earlier version will not match a new one and the first capture after upgrading re-copies its artifact. Grouping fingerprints are unchanged, so existing report directories keep their identity.
- `run_crash_monitor_if_env` no longer clears its own environment marker; the guard in `init` is unaffected. (`native-crash`)

### Security

- Hardening across the writer, the redaction path, the shared-memory breadcrumb ring, and the `native-crash` monitor's IPC. Every string on a report — including backtrace frames, the thread name, and artifact notes — now passes through the configured `Redactor`, and a panic inside an adopter's `Redactor` or `DomainContext` can no longer reach the caller: the capture is abandoned rather than written half-redacted.

### Added

- `faultbox::digest`, a dependency-free SHA-256 — a crash reporter's dependency tree is code that runs inside a failing process.
- `faultbox::secure_fs::validate_artifact_name`, so a caller can check a name before handing it to `Capture::preserve`.
- `redact::MAX_JSON_DEPTH`, `redact::REDACTED_DEPTH`, `shared_ring::MAX_CAPACITY`, and `writer::Staged::discard`.

---

## [0.1.1] - 2026-07-27

A redaction release. `BasicRedactor` recognised one lexical shape for a credential and let every other one through; this fixes that class rather than the two reported instances of it.

### Fixed

- **`BasicRedactor` recognised only one lexical shape, and let every other one through.** The value scanner ended a value at the first terminator byte and the key matcher required a bare name abutting the separator, so a credential leaked whenever it arrived in any other form. Now fixed for: an HTTP auth scheme (`authorization: Bearer <token>` masked only `Bearer`), a quoted value containing a space (`password: "hunter 2"`), a quoted key (`{"api_key":"…"}` and `{"authorization": "…"}` passed through untouched), whitespace around the separator (`token = "…"`, `Authorization : …`, likewise untouched), a hyphenated header key (`x-api-key`), and a quote inside an unquoted value (`secret=don't-tell-anyone`). ([#1](https://github.com/farhan-syah/faultbox/issues/1))
- **A composite value was masked only as far as its first element**, printing the `[redacted]` marker beside the surviving secret — which reads as handled. `Some("…")`, `Credentials("…", "…")`, `["…", "…"]` and `Secret { inner: "…" }` under a credential-naming key now have every leaf inside them masked, with the structure kept. ([#2](https://github.com/farhan-syah/faultbox/issues/2))
- **JSON was redacted per-string, so an object key naming a credential was never seen.** `{"authorization": "Bearer …"}` in a breadcrumb field or `DomainContext` payload passed through in full. Object members are now judged by their key, and a masked leaf becomes the `[redacted]` string whatever its type was.
- **Email masking split on the space character alone**, so a comma-joined list (`ada@example.com,grace@example.com`) leaked both addresses, and an address delimited by a tab or newline swallowed the whole surrounding segment into `[email]`, destroying the line.
- **Home-directory stripping was a plain substring replacement.** It is now case- and separator-insensitive (`C:\Users\Ada` matches `c:/users/ada`) and respects path boundaries, so a home of `/home/ad` no longer corrupts `/home/adam`.
- Two tests in `tests/layered_stack.rs` raced for the process-global `init`, making the outcome depend on test order.

### Added

- **Keyless credential detection.** A credential with no key in front of it — pasted into a retry log, embedded in a URL, echoed inside a stack trace — is masked on its own evidence: issuer prefixes (`sk-`, `ghp_`, `AKIA`, …), JWT structure, or a PEM block. Deliberately not entropy-based, so build-ids, hashes and trace-ids survive.
- **Credential key names are matched by suffix**, so `AZURE_OPENAI_KEY`, `x-api-key` and `apiKey` all resolve. Names that are merely credential-_adjacent_ (`key`, `auth`, `session`, `signature`) form a second tier and mask only a value that is itself credential-shaped, so `grouping_key=kind=0x09` — the field a report is fingerprinted by — stays readable.
- The username is now stripped from paths outside `$HOME` too: `/var/log/ada/store.log` becomes `/var/log/~user/store.log`. Generic and very short usernames are left alone.
- `Redactor::redact_value_for_key` and `Redactor::redact_key`, both default-implemented, so a redactor can act on the key/value relationship a per-string scan never sees. Existing implementations are unaffected.
- `faultbox::redact` module, with `REDACTED` and `REDACTED_EMAIL` exported for redactors composing on top of the markers.

### Changed

- Redaction moved from `faultbox::context` into `faultbox::redact`. `Redactor`, `BasicRedactor` and `NoopRedactor` are re-exported from both the crate root and `faultbox::context`, so no import breaks.
- Redaction allocates once per string rather than once per pass: a string carrying nothing sensitive is now passed through borrowed.

---

## [0.1.0] - 2026-07-26

Initial release.

### Added

- **One report format for every failure class** — Rust panics (installed hook), data corruption, invariant violations, and report-worthy errors (explicit capture at the detection site).
- **Flight-recorder breadcrumbs** — a fixed-size in-memory ring, `breadcrumb!`, inert until `init` runs so libraries may emit unconditionally.
- **`DomainContext`** — per-project forensic payload with a stable `grouping_key`, so like failures fingerprint together across machines. `Adhoc` covers the case where a bespoke type is overkill.
- **Report coalescing** — N occurrences of one fingerprint collapse into one report directory carrying `occurrences`, with the preserved artifact stored once. A crash loop cannot fill the disk it is reporting about.
- **Artifact preservation** — a snapshot of the offending file, content-addressed and deduplicated across sibling reports.
- **Retention** — bounded report directories with a configurable policy.
- **Build-id capture** for offline symbolication, so no debug symbols ship to users.
- **Redaction** — every string entering a report passes through a `Redactor`. `NoopRedactor` by default; `BasicRedactor` covers home directories, credential assignments and email addresses.
- **`reader::list` / `reader::load`** for reading reports back, with a one-line group summary.
- **`native-crash` feature** — out-of-process minidump capture for SIGSEGV, abort and stack overflow, via a re-exec of the host binary as a monitor. Requires `run_crash_monitor_if_env()` as the first statement in `main`.
- **`tracing` feature** — `BreadcrumbLayer` turns existing `tracing` instrumentation into the flight recorder, with no manual breadcrumb calls.
- **`shared-ring` feature** — a breadcrumb ring in shared memory keyed to the artifact rather than the process, so a corruption detected by one process carries the writes that caused it in another. Recovered into a report on native crash.
- Linux, macOS and Windows run the full suite in CI. `wasm32-unknown-unknown` and `wasm32-wasip1` compile and are inert, so the crate is safe to have in the dependency tree of a crate that also targets wasm.

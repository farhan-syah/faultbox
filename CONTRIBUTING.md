# Contributing to faultbox

Thanks for your interest. `faultbox` is a single library crate with a narrow job — capture a failure well enough to debug it from the report alone — so most contributions are small and self-contained.

---

## Where to Start

- **[GitHub Issues](https://github.com/farhan-syah/faultbox/issues)** — bug reports and well-scoped feature requests.

A bug report with a minimal reproducing program is worth more than a long description; the redaction issues that shaped 0.1.1 were both filed that way. For anything that changes the report format, the public API, or the crash-monitor protocol, open an issue before writing the PR.

---

## What This Crate Is

`faultbox` runs at the worst moment in a program's life: inside a panic hook, after a corruption check has failed, or in a monitor process attached to one that is already crashing. Two consequences shape almost every review comment:

- **A failure in `faultbox` must not become the failure.** No panics on paths reachable from the panic hook, no unbounded recursion or allocation on attacker- or corruption-influenced input, no blocking on a lock that a crashing process may hold.
- **A report is worthless if it cannot be submitted.** Everything entering a report passes through a `Redactor`. Adding a field that carries user content, without redacting it, is a data-disclosure bug rather than a style issue.

The crate is synchronous and `std`-only on purpose: it must be callable from a panic hook, and usable by any project regardless of async runtime. Adding an async dependency to the core is not a change we can take.

---

## What We Welcome

- Bug fixes with a reproducing test.
- Redaction coverage: new credential shapes, key names, or serialization forms that leak today.
- Platform fixes — Windows and macOS behaviour around file locking, process spawning, and minidumps is where most portability bugs live.
- Test coverage, especially multi-process and crash-recovery scenarios.
- Documentation fixes.

## What to Discuss First

- Report schema changes. `SCHEMA_VERSION` is read by anything parsing existing reports.
- Public API changes, including new `Redactor` trait methods without defaults.
- The crash-monitor protocol or its re-exec contract.
- The shared-memory ring layout.
- New dependencies. The default build has two (`serde`, `serde_json`); each optional feature carries its own tree and stays optional for that reason.

## What We Don't Accept

- Cosmetic-only changes with no functional effect.
- AI-generated code submitted without the author having reviewed and understood it.
- `#[ignore]` or `.skip` used to make a real coverage gap green. A real test is left red; a speculative one is deleted.
- Issue numbers, phase or wave labels in file names, test names, or comments. Tests outlive issues — a reader two years from now must understand the test without the ticket. Comments explain _behaviour_; test names state _what they assert_.

---

## Development Setup

**Requirements:**

- Rust 1.88 or later (the MSRV in `Cargo.toml`; let-chains and the `native-crash` dependency tree both need it).
- `cargo-nextest` for the test suite.

```bash
cargo install cargo-nextest --locked

git clone https://github.com/farhan-syah/faultbox.git
cd faultbox
cargo nextest run --all-features
```

**Why nextest, not `cargo test`?** The suite spawns real child processes — a crash monitor that re-execs the test helper, several processes contending for one file lock, several writing one mmap'd ring. `.config/nextest.toml` gives those the isolation they need, and deliberately configures **no retries**: these tests assert counts, so a retry would hide a concurrency bug rather than absorb a slow runner.

`cargo test --doc` still runs the doctests, which nextest does not.

---

## Code Standards

Everything below runs in CI and blocks merge. Run them one at a time, not chained:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features --no-fail-fast
cargo deny check
cargo doc --no-deps --all-features   # RUSTDOCFLAGS="-D warnings"
```

CI additionally checks the feature matrix (each feature alone, and none), the MSRV, `wasm32-unknown-unknown` and `wasm32-wasip1`, and `cargo package`.

Key rules:

- No `.unwrap()` or `.expect()` on paths reachable from the panic hook or the crash monitor. A panic during panic handling aborts the process and loses the report.
- `mod.rs` files contain only `pub use` — no types, no logic.
- Prefer many small, focused files over few large ones.
- Unit tests go in the same file under `#[cfg(test)] mod tests`; integration tests go in `tests/` and use the public API only.

---

## Testing

**One `#[test]` per integration test file when the test calls `faultbox::init`.** `init` is once-per-process and the first call wins, so two tests in one binary race for it and the loser writes its reports into the winner's directory. Each file in `tests/` is its own binary, which is the isolation that makes this work.

**Multi-process tests** drive `src/bin/crash_helper.rs`. They are excluded from the published crate, so they may assume the repository layout.

**Redaction tests** assert both the exact rendering and that no fragment of the secret survives anywhere in the output. A silent partial mask is the failure mode being guarded against, and an equality assertion alone tends to get rewritten to match whatever the implementation emits.

When fixing a bug, add the test first and confirm it fails for the reason you think it does. When adding a feature, cover the failure paths as well as the success one.

---

## Commits and Pull Requests

**Commit format** — [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(redact): recognise credential key names by suffix
fix(writer): retry rename onto a destination held open by a reader
docs(readme): document what BasicRedactor does not cover
test(multiprocess): cover a monitor that dies before the crash
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `ci`, `chore`

**One logical change per commit.** If a PR touches several concerns, split it so a reviewer can follow the intent.

**Update `CHANGELOG.md`** under `## [Unreleased]` for anything a user would notice — a fix, a new capability, a behaviour change. Internal refactors that change nothing observable do not need an entry. The release workflow refuses to cut a tag whose version has no changelog section, and publishes that section as the release notes, so this is what your change will be announced as.

**Draft PRs are welcome** — open one early for directional feedback before investing in a full implementation.

**PR description should cover:** what the change does and why, how to test it, and any tradeoff you made.

**Review timeline:** this is a small project; PRs may not be reviewed immediately.

---

## Releasing

Maintainers only, and deliberately manual:

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z]` with the date, and add the link definition at the foot of the file.
2. Set `version` in `Cargo.toml`.
3. Push a `vX.Y.Z` tag. `Release Prepare` validates the tag against `Cargo.toml`, requires the changelog section, runs the full suite, and packages the crate.
4. Dispatch `Release` with that tag and the prepare run ID. It publishes to crates.io and cuts the GitHub release from the changelog section.

Prerelease tags (`vX.Y.Z-beta.N`) are validated against the base version's changelog section, so a beta rehearses the notes the final release will carry.

---

## Security

Do not report security vulnerabilities in public issues. Use [GitHub Security Advisories](https://github.com/farhan-syah/faultbox/security/advisories/new). See [SECURITY.md](SECURITY.md) for what qualifies and how we respond — in particular, a gap in `BasicRedactor` is an ordinary bug, and a public issue for one is welcome.

---

## License

`faultbox` is dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option. Contributions are accepted under the same terms, as described in the Apache-2.0 license. No CLA is required.

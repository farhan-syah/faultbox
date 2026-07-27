# Security Policy

`faultbox` is **pre-1.0**. Interfaces, defaults, and the report schema may change between releases. Security reports are investigated regardless — this policy explains what qualifies, how to report it, and how we respond.

A crash reporter has an unusual security shape: it is code that runs while a process is already failing, and it writes files containing whatever that process was holding. Both halves matter here.

## Supported Versions

While `faultbox` is pre-1.0, fixes are issued **only against the latest released version**.

| Version  | Supported          |
| -------- | ------------------ |
| 0.1.x    | :white_check_mark: |

Always run the latest release; it carries every prior fix.

## What Qualifies as a Security Vulnerability

In scope:

- **Writing outside the configured reports directory** — path traversal through a project name, domain kind, or preserved-artifact path; following a symlink out of the directory; or clobbering a file the adopter did not expect to be written.
- **Disclosing data the adopter's own `Redactor` was supposed to remove** — a string that reaches a report without passing through the configured redactor at all, or a path that bypasses `redact_json` for domain payloads or breadcrumb fields.
- **Anything reachable from the crash-monitor IPC.** The `native-crash` monitor accepts a connection from the crashing process; a local process that can reach that socket and thereby cause the monitor to write, read, or execute something it should not is in scope.
- **Anything reachable through the shared-memory ring.** With `shared-ring`, several processes map one region. Memory-safety issues, or a malicious writer inducing unsafe behaviour in a reader, are in scope.
- **Memory-safety issues or arbitrary code execution** reachable from any of the above, or from parsing a report with `reader::load`.
- **A panic, abort, or infinite loop inside the panic hook or the crash monitor** triggered by ordinary program data. Losing the report is bad; turning a recoverable failure into an abort is worse.
- **Reports written with permissions that expose them** beyond what the adopter configured.

Generally **not** vulnerabilities — still worth reporting as ordinary bugs, in public issues:

- **A gap in `BasicRedactor`.** It is documented as a best-effort default, not a compliance boundary: a starting point that projects handling regulated data compose their own redactor on top of. Missed credential shapes are real bugs and are fixed promptly — [#1](https://github.com/farhan-syah/faultbox/issues/1) and [#2](https://github.com/farhan-syah/faultbox/issues/2) were exactly that — but a public issue with a reproducing program is the right channel, and gets the fix faster.
- **Data an adopter deliberately put in a report.** `DomainContext` payloads are supplied by the adopting project; a project that puts user content there and configures `NoopRedactor` — the default — has made that choice.
- **Anything requiring an attacker who can already write to the reports directory, the process's memory, or its environment.** At that point the report is the least of it.
- **Vulnerabilities in third-party dependencies already tracked by their own advisory.** Please still tell us so we can upgrade.
- **Issues in development tooling** (`src/bin/crash_helper.rs`, CI scripts, tests) that do not affect the published crate.

If you are unsure, err on the side of reporting privately.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Report privately through GitHub Security Advisories:

> [Report a vulnerability](https://github.com/farhan-syah/faultbox/security/advisories/new)

Or use the repository's **Security** tab → **Advisories** → **Report a vulnerability**. This opens a private channel between you and the maintainers; nothing is public until an advisory is published.

Please include:

- **Overview** — the issue and its security impact.
- **Affected version** — the `faultbox` version, and which features were enabled (`native-crash`, `tracing`, `shared-ring`).
- **Reproduction** — a minimal program, or step-by-step instructions.
- **Environment** — OS and architecture. Much of this crate's surface is platform-specific.
- **Evidence** — proof-of-concept code, a report directory listing, log excerpts, a stack trace, or a patch if you have one.
- Whether the issue is already public or under coordinated disclosure elsewhere.

## Our Response

When you report an issue we will:

1. **Acknowledge** receipt within **3 business days**.
2. Give an **initial assessment** — confirmed, needs more information, or not a vulnerability, with severity and scope — within **10 business days**.
3. Keep you **updated at least every 14 days** while a fix is in progress.
4. Prepare the fix, cut a release, and **publish a GitHub Security Advisory once the fixed release is on crates.io** — unless the issue is already public.

We coordinate disclosure: reporter and maintainers agree an embargo, typically up to 90 days and shorter for actively-exploited issues, and we ask that the issue not be disclosed publicly until a fixed release is out.

## CVEs

Advisories are published through GitHub Security Advisories, which acts as the CVE Numbering Authority; we request a CVE when an issue warrants one. Pre-1.0, many advisories will carry a GHSA identifier only. Please **do not register a CVE independently** — coordinate through the advisory so the record stays accurate.

Published advisories are listed on the repository's [Security Advisories](https://github.com/farhan-syah/faultbox/security/advisories) page.

There is no bug bounty.

## Credit and Safe Harbor

Reporters are credited in the advisory and release notes by default. Say so in your report if you would rather stay anonymous or use a specific handle.

Security research conducted in good faith under this policy is authorized, and we will not pursue legal action for it. In return we ask that you:

- Give us reasonable time to fix the issue before public disclosure.
- Use only the access needed to demonstrate the issue, and do not exfiltrate data that is not yours.
- Do not test against infrastructure you do not own.

## Scope

In scope: the `faultbox` crate published on crates.io and this repository's library sources, including the crash-monitor protocol, the shared-memory ring layout, the on-disk report layout, and the reader.

Out of scope: the adopting application's own `DomainContext` and `Redactor` implementations, third-party dependencies already covered by their own advisory, and the non-vulnerability categories above.

## Security Practices

- Dependencies are audited in CI with **`cargo deny check`** against the RustSec advisory database, plus license and source-ban policy.
- Clippy runs with warnings denied, across all targets and all features.
- The suite runs on Linux, macOS and Windows, because the process-spawning, file-locking and shared-memory paths differ per platform and are where memory-safety and race bugs live.
- Redaction is covered by a generative test asserting that arbitrary input never panics, always reaches a fixed point, and never leaves a credential in the output.

## Hardening Notes for Adopters

- **Set a `Redactor` explicitly.** The default is `NoopRedactor`, which changes nothing. `BasicRedactor` is a sensible starting point; regulated data warrants your own on top of it.
- **Keep the reports directory private to the service account** that writes it, and treat it as data at rest — reports contain preserved artifacts and breadcrumb payloads.
- **Treat a report as sensitive until you have read one.** Look at what your `DomainContext` actually emits before enabling submission.
- **Call `run_crash_monitor_if_env()` as the first statement in `main`** when `native-crash` is enabled. It is a re-exec of your own binary; anything running before it runs again in the monitor process.
- **Configure retention.** Reports are bounded but not zero-cost, and coalescing only collapses repeats of the same fingerprint.

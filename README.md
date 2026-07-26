# blackbox

A production black-box recorder for Rust services: structured crash, corruption, and invariant-violation reports carrying a flight-recorder breadcrumb trail.

The goal is to debug a production failure **from its report**, without a reproduction and without shipping debug symbols to users.

```toml
[dependencies]
blackbox = "0.1"
```

## Why this exists

Panic-only crash reporters miss the failures that matter most in a storage engine. Data corruption and violated invariants are usually *returned errors* — `Err(ChecksumFailure)`, not a `panic!` — so nothing installs a hook for them, and they reach a user as a log line with no context. By the time anyone looks, the process that caused the damage is gone.

`blackbox` captures every failure class through one report format:

| Class | How it is captured |
| --- | --- |
| Rust panic | installed panic hook |
| Native crash (SIGSEGV, abort, stack overflow) | out-of-process minidump |
| Data corruption | explicit capture at the detection site |
| Invariant violation | explicit capture at the detection site |
| Report-worthy error | explicit capture at the detection site |

Each report carries the breadcrumb trail leading up to the failure, a build-id for offline symbolication, project-specific forensic context, and — for corruption — a preserved snapshot of the bad artifact.

## Usage

### Initialize once at startup

```rust
use blackbox::{BasicRedactor, Config};

blackbox::init(
    Config::new("myapp", env!("CARGO_PKG_VERSION"), "/var/lib/myapp/reports")
        .git_sha(env!("GIT_SHA"))
        .redactor(Box::new(BasicRedactor::new())),
);
```

### Get a breadcrumb trail for free

If the project already uses `tracing`, the `tracing` feature turns existing instrumentation into the flight recorder — no manual breadcrumb calls:

```rust
use tracing_subscriber::prelude::*;

tracing_subscriber::registry()
    .with(blackbox::BreadcrumbLayer::new().only_targets(["myapp"]))
    .init();
```

Otherwise, place breadcrumbs by hand at significant operations. They are a no-op until `init` runs, so libraries may emit them unconditionally:

```rust
blackbox::breadcrumb!(Info, "myapp.commit", "committed", { "commit_id": 9558 });
```

### Capture at the detection site

```rust
use blackbox::{Capture, EventKind};

let _ = Capture::new(EventKind::Corruption, "internal node references a non-btree page")
    .error_chain(blackbox::error_chain_of(&err))
    .domain(&ctx)                       // your DomainContext impl
    .preserve("store-snapshot", &store_path, "store.corrupt", None)
    .emit();
```

`DomainContext` is the per-project extension point. Its `grouping_key` should identify the *class* of failure, never the instance — `"child_kind=0x09"`, not the page id that happened to be involved — so the same bug groups together across machines.

### Read reports back

```rust
for group in blackbox::reader::list("/var/lib/myapp/reports")? {
    println!("{}", group.summary());
    // corruption  ×412  4121763d  store.dangling_child  internal node references …
}
```

## Reports coalesce by bug, not by occurrence

A report directory is keyed by fingerprint and holds:

```
<reports_dir>/<fingerprint>/
├── report.json      first capture, plus occurrences / first_seen / last_seen
├── latest.json      most recent capture (only once a bug repeats)
└── store.corrupt/   preserved artifact, stored once
```

A crash loop re-detecting one bug increments a counter instead of writing a new directory each time. This is not cosmetic: under a supervised restart loop, a per-occurrence layout writes thousands of directories for a single bug, each with its own copy of the store. Retention caps the directory (default 64 groups / 2 GiB), because a recorder that fills the disk of the process it monitors has done more damage than the bug it recorded.

## Feature flags

All are off by default; the base crate depends only on `serde` and `serde_json`.

| Feature | What it adds |
| --- | --- |
| `tracing` | `BreadcrumbLayer`, feeding the flight recorder from `tracing` events |
| `shared-ring` | breadcrumb ring in shared memory, keyed to the artifact rather than the process |
| `native-crash` | out-of-process minidump capture for SIGSEGV / abort / stack overflow |

### `shared-ring`: corruption caused elsewhere

An in-process breadcrumb ring can only show what *this* process did. When corruption is written by one process and detected when another opens the store, the detecting process's trail is structurally the wrong trail.

A `SharedRing` lives in a memory-mapped file beside the store, so every process touching it appends to one trail and a report can show the writes that actually caused the damage:

```rust
let ring = std::sync::Arc::new(blackbox::shared_ring::SharedRing::open(
    store_path.join(".blackbox-ring"),
    512,
)?);
blackbox::init(Config::new(/* … */).shared_ring(ring));
```

It uses no locks — a slot is claimed with one atomic increment and published with a seqlock — so a process killed mid-write costs exactly one breadcrumb and can never wedge the ring for anyone else.

### `native-crash` requires one line in `main`

The monitor is a re-exec of the host binary, so it needs `main` to identify itself. **This call is mandatory** whenever the handler is armed:

```rust
fn main() {
    if blackbox::run_crash_monitor_if_env() {
        return;
    }
    // ...normal startup
}
```

Without it, each spawned monitor runs the application again and spawns another monitor — exponentially. For that reason the handler is **off by default** even when the Cargo feature is enabled, and must be armed explicitly:

```rust
Config::new(/* … */).install_native_crash_handler(true)
```

`init` detects a failed-to-divert monitor and exits it rather than letting it multiply, but that is a backstop, not a substitute for the call.

## Redaction

Every string entering a report — messages, error chains, breadcrumbs, domain values — passes through a `Redactor`. `BasicRedactor` strips the home directory, masks `key=value` pairs naming a secret, and masks email addresses. It is a sensible default, not a compliance boundary: projects handling regulated data should compose their own on top.

The default is `NoopRedactor`, so set one explicitly before reports leave a machine.

## Stability

Pre-1.0, the on-disk report shape is changed in place as the crate learns what triage actually needs. There are no migrations and no compatibility shims — reports are short-lived diagnostic artifacts, so delete a stale reports directory rather than parsing an older layout.

## License

MIT OR Apache-2.0.

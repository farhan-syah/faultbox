# faultbox

A production black-box recorder for Rust services: structured crash, corruption, and invariant-violation reports carrying a flight-recorder breadcrumb trail.

The goal is to debug a production failure **from its report**, without a reproduction and without shipping debug symbols to users.

```toml
[dependencies]
faultbox = "0.1"
```

## Why this exists

Panic-only crash reporters miss the failures that matter most in a storage engine. Data corruption and violated invariants are usually _returned errors_ — `Err(ChecksumFailure)`, not a `panic!` — so nothing installs a hook for them, and they reach a user as a log line with no context. By the time anyone looks, the process that caused the damage is gone.

`faultbox` captures every failure class through one report format:

| Class                                         | How it is captured                     |
| --------------------------------------------- | -------------------------------------- |
| Rust panic                                    | installed panic hook                   |
| Native crash (SIGSEGV, abort, stack overflow) | out-of-process minidump                |
| Data corruption                               | explicit capture at the detection site |
| Invariant violation                           | explicit capture at the detection site |
| Report-worthy error                           | explicit capture at the detection site |

Each report carries the breadcrumb trail leading up to the failure, a build-id for offline symbolication, project-specific forensic context, and — for corruption — a preserved snapshot of the bad artifact.

## When to use it

The question that decides it is not how long your process lives, it is: **does your software detect failures it cannot reproduce?**

Good fit:

- Storage engines, databases, file-format parsers, sync engines — anything that checks a checksum or an invariant at runtime and can therefore discover that its own data is wrong.
- Code that crosses into C or C++ through FFI, where a fault arrives as SIGSEGV rather than a panic. `std::panic::set_hook` cannot see those.
- Long-running services and desktop applications, where a crash otherwise leaves nothing behind.

Poor fit:

- `no_std` and embedded targets. This crate is std-only.
- Software whose only realistic failure is a panic, already reported somewhere. A panic-only reporter is simpler and does that job.

**Libraries are a good fit, and are expected to be one.** A library should not call `init`, install hooks, or choose the reports directory — that belongs to the binary. But a library that detects its own corruption *should* report it, and everything here stays inert until an application initializes, so depending on it costs a library nothing. See [Using it across a dependency stack](#using-it-across-a-dependency-stack).

## Usage

### Initialize once at startup

```rust
use faultbox::{BasicRedactor, Config};

faultbox::init(
    Config::new("myapp", env!("CARGO_PKG_VERSION"), "/var/lib/myapp/reports")
        .git_sha(env!("GIT_SHA"))
        .redactor(Box::new(BasicRedactor::new())),
);
```

### Full startup: `tracing` and native-crash capture together

Everything wired up, in the order it has to happen:

```rust
use tracing_subscriber::prelude::*;

fn main() {
    // 1. FIRST statement in main. This process may be the crash monitor — a
    //    re-exec of this same binary — in which case it serves minidumps here
    //    and never returns. Mandatory whenever the handler is armed below.
    if faultbox::run_crash_monitor_if_env() {
        return;
    }

    // 2. Initialize the recorder. Only the binary does this, and only once.
    faultbox::init(
        faultbox::Config::new("myapp", env!("CARGO_PKG_VERSION"), "/var/lib/myapp/reports")
            .redactor(Box::new(faultbox::BasicRedactor::new()))
            .features(["encryption", "compression"])
            // Spawns the out-of-process monitor. Safe because of step 1.
            .install_native_crash_handler(true),
    );

    // 3. Install the tracing layer, so events the app already emits become the
    //    flight recorder.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(faultbox::BreadcrumbLayer::new().only_targets(["myapp"]))
        .init();

    run_app();
}
# fn run_app() {}
```

Steps 2 and 3 can be swapped — `BreadcrumbLayer` feeds a ring that is inert until `init` runs, and `init` does not depend on `tracing`. Step 1 cannot move: it must precede all other work, including argument parsing.

### Get a breadcrumb trail for free

If the project already uses `tracing`, the `tracing` feature turns existing instrumentation into the flight recorder — no manual breadcrumb calls:

```rust
use tracing_subscriber::prelude::*;

tracing_subscriber::registry()
    .with(faultbox::BreadcrumbLayer::new().only_targets(["myapp"]))
    .init();
```

Otherwise, place breadcrumbs by hand at significant operations. They are a no-op until `init` runs, so libraries may emit them unconditionally:

```rust
faultbox::breadcrumb!(Info, "myapp.commit", "committed", { "commit_id": 9558 });
```

### Capture at the detection site

```rust
use faultbox::{Capture, EventKind};

let _ = Capture::new(EventKind::Corruption, "internal node references a non-btree page")
    .error_chain(faultbox::error_chain_of(&err))
    .domain(&ctx)                       // your DomainContext impl
    .preserve("store-snapshot", &store_path, "store.corrupt", None)
    .emit();
```

`DomainContext` is the per-project extension point. Its `grouping_key` should identify the _class_ of failure, never the instance — `"child_kind=0x09"`, not the page id that happened to be involved — so the same bug groups together across machines.

`emit` is synchronous and does real filesystem work (digest, copy, fsync, a lock). That is deliberate — it must be callable from a panic hook, where an async runtime may no longer be usable. In an async application, call it from `spawn_blocking` (or equivalent) so a failure report cannot stall an executor thread.

### Read reports back

```rust
for group in faultbox::reader::list("/var/lib/myapp/reports")? {
    println!("{}", group.summary());
    // corruption  ×412  4121763d  store.dangling_child  internal node references …
}
```

## Using it across a dependency stack

When several layers of one stack use `faultbox` — a storage engine, the database built on it, the application on top — they share a single recorder per process. Four rules follow.

**Only the binary calls `init`.** It is once-per-process and the first call wins; a later one returns `false` and changes nothing, not even partially. A library that calls `init` therefore either silently loses or silently decides the reports directory and redactor for everyone. Libraries only emit breadcrumbs, which are inert until the application initializes.

**Breadcrumbs merge; they do not duplicate.** Every layer records into one ring, so the trail interleaves in call order with each crumb recorded exactly once. This is the payoff: a report filed deep in the storage engine still carries the query that led to the bad read.

**Report at the detection site.** One `emit` is one report. If each layer emits on the way up, you get three reports for one root cause — `faultbox` cannot tell they are related, since each has its own domain kind and fingerprint. The layer that knows the invariant is the layer that reports it; layers above add breadcrumbs and propagate the error.

**Make sure there is exactly one `faultbox` in the graph.** This is the quiet one. If crate A depends on it by path and crate B by version, Cargo treats those as different packages and compiles **both** — giving two independent sets of process-wide state. The application initializes one; every `emit` through the other returns `None` and disappears, with no error and no report. The same applies to two semver-incompatible versions. Resolve all of them to one source (`[patch]`, a shared path, or a single published version), and check with `cargo tree -d`.

Attribution still works across layers: `meta.project` names the process, while `domain_kind` records which layer detected the failure.

Feature flags are unioned by Cargo, so if any crate in the graph enables `native-crash`, it is compiled into everything. That is harmless — arming the handler is a separate, explicit decision the application makes.

## Reports coalesce by bug, not by occurrence

A report directory is keyed by fingerprint and holds:

```
<reports_dir>/<fingerprint>/
├── report.json      first capture, plus occurrences / first_seen / last_seen
├── latest.json      most recent capture (only once a bug repeats)
└── store.corrupt/   preserved artifact, stored once
```

A crash loop re-detecting one bug increments a counter instead of writing a new directory each time. This is not cosmetic: under a supervised restart loop, a per-occurrence layout writes thousands of directories for a single bug, each with its own copy of the store. Retention caps the directory, because a recorder that fills the disk of the process it monitors has done more damage than the bug it recorded.

Because coalescing hides the true failure count behind a small directory listing, `reader::total_occurrences` gives you the honest number.

The limits are all configurable:

```rust
use faultbox::Retention;

Config::new(/* … */)
    .breadcrumb_capacity(256)                  // ring size; default 128
    .preserve_max_bytes(64 * 1024 * 1024)      // artifact cap; default 256 MiB
    .retention(Retention {
        max_groups: 32,                        // default 64
        max_total_bytes: 512 * 1024 * 1024,    // default 2 GiB
    })
```

An artifact over the cap is not copied, and the report records that it was skipped and where the source is — a missing snapshot is stated, never merely absent. Digesting and copying happen before the group lock is taken, so preserving a large store never blocks another process's report.

## Feature flags

All are off by default; the base crate depends only on `serde` and `serde_json`.

| Feature        | What it adds                                                                    |
| -------------- | ------------------------------------------------------------------------------- |
| `tracing`      | `BreadcrumbLayer`, feeding the flight recorder from `tracing` events            |
| `shared-ring`  | breadcrumb ring in shared memory, keyed to the artifact rather than the process |
| `native-crash` | out-of-process minidump capture for SIGSEGV / abort / stack overflow            |

### `shared-ring`: corruption caused elsewhere

An in-process breadcrumb ring can only show what _this_ process did. When corruption is written by one process and detected when another opens the store, the detecting process's trail is structurally the wrong trail.

A `SharedRing` lives in a memory-mapped file beside the store, so every process touching it appends to one trail and a report can show the writes that actually caused the damage:

```rust
let ring = std::sync::Arc::new(faultbox::shared_ring::SharedRing::open(
    store_path.join(".faultbox-ring"),
    512,
)?);
faultbox::init(Config::new(/* … */).shared_ring(ring));
```

It uses no locks — a slot is claimed with one atomic increment and published with a seqlock — so a process killed mid-write costs exactly one breadcrumb and can never wedge the ring for anyone else.

An existing ring is joined as-is and **its** capacity is adopted, even if this caller asked for a different one; `capacity()` reports what you actually got. Resizing a file that other processes have mapped would leave their mappings pointing past end-of-file, and their next breadcrumb would take SIGBUS — a recorder must not be able to kill the processes it is watching because two of them disagreed about a number.

Because the ring is a file, it also outlives the process that wrote it. With `native-crash` enabled as well, the crash monitor recovers the trail after a fatal signal and writes it into the report — so a native crash arrives with the operations that led up to it instead of a bare minidump. The in-process recorder cannot do this: it dies with the process, and a signal handler could not read it in any case, because it sits behind a `Mutex`.

Crumbs are redacted on the way *into* the ring rather than on the way out of a report. The monitor is a separate process with no access to your `Redactor`, so anything written to the ring has to be safe already.

### `native-crash` requires one line in `main`

The monitor is a re-exec of the host binary, so it needs `main` to identify itself. **This call is mandatory** whenever the handler is armed:

```rust
fn main() {
    if faultbox::run_crash_monitor_if_env() {
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

## Platform support

Requires `std`; there is no `no_std` build. Linux, macOS, and Windows run the full test suite in CI.

`wasm32-unknown-unknown` compiles and is **inert**: breadcrumbs are recorded in memory, but there is no filesystem to write a report to and no signals to catch. It is safe to have in the dependency tree of a crate that also targets wasm — linking it will not break the build or panic at runtime — but nothing is captured there. `wasm32-wasip1` is compile-checked too.

`native-crash` and `shared-ring` are host-only. They are off by default, so a wasm or minimal build never pulls in `crash-handler`, `minidumper`, or `memmap2`.

## Stability

Pre-1.0, the on-disk report shape is changed in place as the crate learns what triage actually needs. There are no migrations and no compatibility shims — reports are short-lived diagnostic artifacts, so delete a stale reports directory rather than parsing an older layout.

## License

MIT OR Apache-2.0.

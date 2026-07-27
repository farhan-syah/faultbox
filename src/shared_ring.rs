// SPDX-License-Identifier: MIT OR Apache-2.0

//! A breadcrumb ring in shared memory, keyed to the *artifact* instead of the
//! process.
//!
//! ## Why a second ring exists
//!
//! The in-process flight recorder ([`crate::breadcrumbs`]) can only ever show
//! what *this* process did. But the corruption that motivated this crate is
//! caused by one process's writes and detected by a different process's open —
//! so the detecting process's trail is, structurally, the wrong trail. It shows
//! the reopen that noticed the damage and nothing about the writes that did it.
//!
//! A [`SharedRing`] is a fixed-size ring buffer in a memory-mapped file that
//! lives beside the artifact (the store), so every process that touches that
//! store appends to the same trail. A corruption report can then carry the last
//! writes *from whichever process made them*.
//!
//! ## Crash safety
//!
//! Every writer that touches this file is, by assumption, a process that may be
//! killed mid-write — that is the entire scenario. So the ring uses no locks
//! that could be left held:
//!
//! - A writer claims a slot with one atomic `fetch_add` on a shared ticket
//!   counter. No lock, so nothing to leak.
//! - Each slot is a seqlock: the sequence number is set *odd* before the body is
//!   written and *even* after. A reader that sees an odd sequence — or a
//!   sequence that changed while it was reading — skips that slot.
//! - A process dying mid-slot therefore costs exactly one breadcrumb. It cannot
//!   wedge, poison, or corrupt the ring for anyone else.
//!
//! Slots are fixed-size and messages are truncated to fit, so recording never
//! allocates and never blocks.
//!
//! ## Trust boundary
//!
//! The ring file is shared mutable state. Only processes already trusted with
//! the artifact should be able to write it, so it is created owner-only and a
//! deployment that genuinely shares a store between accounts must widen it
//! deliberately. A hostile writer can garble the trail (it cannot escape the
//! mapping: every read is bounds-checked and every string is validated UTF-8),
//! but a hostile writer with access to the store has better things to corrupt.
//!
//! ## Why every byte is an atomic
//!
//! Other processes write this mapping while we read it. Forming a `&[u8]` or a
//! `&mut [u8]` over memory that can change underneath the reference is undefined
//! behaviour in Rust — a data race — no matter how carefully the seqlock
//! sequences the *logical* reads and writes. The seqlock decides which crumbs
//! are trustworthy; it cannot make a racing non-atomic access defined.
//!
//! So the mapping is never viewed as a slice. Payload bytes are read and written
//! one relaxed [`AtomicU8`] at a time, and a reader copies the slot into local
//! memory before parsing it, so all the shape-checking happens on bytes nothing
//! else can touch. Relaxed suffices because the sequence number's
//! release/acquire pair supplies the ordering.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use memmap2::MmapMut;

use crate::breadcrumbs::{Breadcrumb, Level};

/// `"FBXRING1"` — identifies the file and its layout. A file that does not
/// start with this is reinitialized rather than parsed.
const MAGIC: u64 = u64::from_le_bytes(*b"FBXRING1");

/// Bytes per slot. Fixed so a writer never allocates and a reader never has to
/// trust a length to find the next record. 256 leaves ~230 bytes of text, which
/// comfortably holds `myapp.commit` + a short message + a few numbers.
const SLOT: usize = 256;
/// Byte offsets within a slot: sequence, timestamp, level, category length,
/// message length, then the payload.
const SLOT_SEQ: usize = 0;
const SLOT_TS: usize = 8;
const SLOT_LEVEL: usize = 16;
const SLOT_CAT_LEN: usize = 17;
const SLOT_MSG_LEN: usize = 18;
/// The pid that recorded the crumb. This is what makes a shared trail readable:
/// without it, writes from three processes interleave into one anonymous list.
const SLOT_PID: usize = 20;
const SLOT_PAYLOAD: usize = 24;
const PAYLOAD_CAP: usize = SLOT - SLOT_PAYLOAD;

/// Header: magic, capacity, then the shared ticket counter.
const HDR_MAGIC: usize = 0;
const HDR_CAPACITY: usize = 8;
const HDR_TICKET: usize = 16;
const HEADER: usize = 64;

/// The largest ring this crate will create: 1M slots, a 256 MiB mapping.
/// [`SharedRing::open`] clamps to it.
///
/// A bound rather than a comment, because the file length is
/// `HEADER + capacity * SLOT` and `capacity` arrives from the caller. Left
/// unchecked, a large value wraps that multiplication in a release build: the
/// file is then created *small* while the ring keeps addressing the capacity it
/// was asked for, and the very first `record` writes far past the end of the
/// mapping. A breadcrumb ring has no legitimate use anywhere near this size, so
/// the cap costs nothing and removes the overflow entirely.
pub const MAX_CAPACITY: usize = 1 << 20;

/// A bounded breadcrumb trail shared by every process that opens the same file.
///
/// Open one per artifact and hand it to [`crate::Config::shared_ring`]; crumbs
/// then go to both the in-process recorder and this ring, and reports carry the
/// merged trail.
pub struct SharedRing {
    map: MmapMut,
    capacity: u64,
    path: PathBuf,
}

// The mapping is shared, and every access goes through atomics or through
// bounds-checked byte copies, so concurrent use from several threads (and
// several processes) is exactly what it is built for.
unsafe impl Send for SharedRing {}
unsafe impl Sync for SharedRing {}

impl SharedRing {
    /// Open (creating if absent) the shared ring at `path`, with room for
    /// `capacity` breadcrumbs *if this call is the one that creates it*.
    ///
    /// An existing, well-formed ring is **joined as-is**: its crumbs are kept
    /// and its own capacity is adopted, even when it differs from `capacity`.
    /// Use [`capacity`](Self::capacity) to see what was actually joined.
    ///
    /// Adopting rather than resizing is a safety requirement, not a
    /// convenience. The file is mapped into every participating process; a
    /// second opener that shrank it to its own preferred size would leave every
    /// existing mapping pointing past end-of-file, and the next breadcrumb
    /// those processes recorded would take SIGBUS. A recorder must not be able
    /// to kill the healthy processes it is monitoring because two of them
    /// disagreed about a capacity.
    ///
    /// A file that is absent, empty, or not a recognizable ring is (re)created
    /// at the requested capacity, clamped to [`MAX_CAPACITY`].
    pub fn open(path: impl AsRef<Path>, capacity: usize) -> io::Result<SharedRing> {
        let capacity = capacity.clamp(1, MAX_CAPACITY);
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            crate::secure_fs::create_dir_all_private(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        // Owner-only on creation. The trail is redacted on the way in, but it
        // still describes what the process was doing, and a ring beside a store
        // has no reason to be readable by other local accounts.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path)?;

        // Join an existing ring if the file already describes one coherently.
        if let Some(ring) = Self::try_join(&file, path)? {
            return Ok(ring);
        }

        // Not a usable ring: create it at the requested capacity. Checked even
        // though `capacity` is clamped above, so that a future change to the
        // clamp cannot silently reintroduce a wrapping length.
        let len = capacity
            .checked_mul(SLOT)
            .and_then(|body| body.checked_add(HEADER))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "shared ring capacity overflows the addressable file length",
                )
            })?;
        file.set_len(len as u64)?;
        // SAFETY: the file was just sized to `len` and stays mapped for the
        // lifetime of the value; concurrent mutation by other processes is the
        // intended design and every access is atomic or bounds-checked.
        let map = unsafe { MmapMut::map_mut(&file)? };
        let ring = SharedRing {
            map,
            capacity: capacity as u64,
            path: path.to_path_buf(),
        };
        ring.header(HDR_TICKET).store(0, Ordering::Release);
        for slot in 0..capacity {
            // The file was just sized to hold every one of these, so `slot_base`
            // cannot refuse — but going through it keeps the bounds check on the
            // one path that writes every slot in the ring.
            if let Some(base) = ring.slot_base(slot as u64) {
                ring.slot_seq_at(base).store(0, Ordering::Release);
            }
        }
        ring.header(HDR_CAPACITY)
            .store(capacity as u64, Ordering::Release);
        // Magic last: until it is set, a concurrent opener treats the file as
        // not-yet-a-ring rather than reading a half-built one.
        ring.header(HDR_MAGIC).store(MAGIC, Ordering::Release);
        Ok(ring)
    }

    /// Join an existing ring **without ever creating or resizing one**.
    ///
    /// Returns `None` when `path` is absent or is not a coherent ring. This is
    /// what a post-mortem reader wants: the crash monitor attaches to the dead
    /// process's trail, and must not conjure an empty ring if the path is wrong
    /// — that would silently report "no breadcrumbs" instead of "misconfigured".
    pub fn join(path: impl AsRef<Path>) -> io::Result<Option<SharedRing>> {
        let path = path.as_ref();
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Self::try_join(&file, path)
    }

    /// Map `file` as a ring if its header is coherent with its actual size.
    fn try_join(file: &std::fs::File, path: &Path) -> io::Result<Option<SharedRing>> {
        let existing = file.metadata()?.len();
        if existing < HEADER as u64 {
            return Ok(None);
        }
        // SAFETY: the file is at least HEADER bytes and stays mapped for the
        // lifetime of the value; concurrent mutation by other processes is the
        // intended design and every access is atomic or bounds-checked.
        let map = unsafe { MmapMut::map_mut(file)? };
        let ring = SharedRing {
            map,
            capacity: 1,
            path: path.to_path_buf(),
        };
        let magic = ring.header(HDR_MAGIC).load(Ordering::Acquire);
        let found = ring.header(HDR_CAPACITY).load(Ordering::Acquire);
        // The header must agree with the file's actual size, or it is not a
        // ring we can safely address.
        let coherent = magic == MAGIC
            && found > 0
            && usize::try_from(found)
                .ok()
                .and_then(|c| c.checked_mul(SLOT))
                .and_then(|b| b.checked_add(HEADER))
                .is_some_and(|want| want as u64 == existing);
        Ok(coherent.then(|| SharedRing {
            capacity: found,
            ..ring
        }))
    }

    /// The capacity actually in use — the creator's, which may differ from the
    /// value this process passed to [`open`](Self::open).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// The file backing this ring. The crash monitor is told this path so it can
    /// recover the trail of a process that has already died.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a breadcrumb. Never blocks, never allocates, and silently
    /// truncates text that does not fit a slot.
    pub fn record(&self, level: Level, category: &str, message: &str) {
        // Claim a slot. `fetch_add` is atomic across processes in a shared
        // mapping, so two processes can never claim the same ticket.
        let ticket = self.header(HDR_TICKET).fetch_add(1, Ordering::AcqRel);
        let slot = ticket % self.capacity;
        // Refuse rather than write outside the mapping if the header ever
        // disagrees with the file's real length. Nothing should be able to get
        // here — `open` and `try_join` both prove the two agree — so this is the
        // backstop that keeps a corrupt header a lost trail, not a memory bug.
        let Some(base) = self.slot_base(slot) else {
            return;
        };

        // Mark the slot in-flight (odd) before touching the body, so a reader —
        // or a reader in another process after we are killed — knows not to
        // trust it.
        let seq = self.slot_seq_at(base);
        seq.store((ticket << 1) | 1, Ordering::Release);

        let cat = clamp_utf8(category, PAYLOAD_CAP.min(u8::MAX as usize));
        let msg = clamp_utf8(message, PAYLOAD_CAP - cat.len());

        // Byte-at-a-time relaxed atomics rather than a slice: another process
        // may be reading this slot right now, and a `&mut [u8]` over memory it
        // can observe is a data race. Offsets stay within the slot by
        // construction — `cat.len() + msg.len() <= PAYLOAD_CAP`.
        self.write(base + SLOT_TS, &(crate::now_ms() as u64).to_le_bytes());
        self.write(base + SLOT_LEVEL, &[level_byte(level)]);
        self.write(base + SLOT_PID, &std::process::id().to_le_bytes());
        self.write(base + SLOT_CAT_LEN, &[cat.len() as u8]);
        self.write(base + SLOT_MSG_LEN, &(msg.len() as u16).to_le_bytes());
        self.write(base + SLOT_PAYLOAD, cat.as_bytes());
        self.write(base + SLOT_PAYLOAD + cat.len(), msg.as_bytes());

        // Publish: even sequence means "this slot is complete". The release
        // pairs with the reader's acquire and orders every byte above.
        seq.store(ticket << 1, Ordering::Release);
    }

    /// Read the trail, oldest first.
    ///
    /// Slots that are mid-write, or that were abandoned by a process that died
    /// while writing them, are skipped — one lost crumb, never a lost trail.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Breadcrumb> {
        let mut out: Vec<(u64, Breadcrumb)> = Vec::new();
        for slot in 0..self.capacity {
            let Some(base) = self.slot_base(slot) else {
                continue;
            };
            let seq_cell = self.slot_seq_at(base);
            let before = seq_cell.load(Ordering::Acquire);
            if before & 1 == 1 {
                continue; // in flight, or abandoned by a dead writer
            }
            let Some(crumb) = self.read_slot(base) else {
                continue;
            };
            // Re-check: a writer may have overwritten this slot underneath us.
            if seq_cell.load(Ordering::Acquire) != before {
                continue;
            }
            // Ticket 0 in an untouched slot is indistinguishable from the very
            // first record; an all-zero slot has no category, so drop it.
            if crumb.category.is_empty() && crumb.message.is_empty() {
                continue;
            }
            out.push((before >> 1, crumb));
        }
        out.sort_by_key(|(ticket, _)| *ticket);
        out.into_iter().map(|(_, c)| c).collect()
    }

    /// Parse the slot beginning at `base`, which must have come from
    /// [`slot_base`](Self::slot_base).
    fn read_slot(&self, base: usize) -> Option<Breadcrumb> {
        // Copy the whole slot out before looking at any of it. Parsing straight
        // from the mapping would mean reading bytes another process can rewrite
        // mid-parse — and would also let a length validated in one read differ
        // from the one used in the next. Local bytes have neither problem; if
        // the copy was torn, the caller's sequence re-check discards it.
        let mut body = [0u8; SLOT];
        self.read(base, &mut body);

        let ts = u64::from_le_bytes(body[SLOT_TS..SLOT_TS + 8].try_into().ok()?);
        let level = byte_level(body[SLOT_LEVEL]);
        let cat_len = body[SLOT_CAT_LEN] as usize;
        let msg_len =
            u16::from_le_bytes(body[SLOT_MSG_LEN..SLOT_MSG_LEN + 2].try_into().ok()?) as usize;
        // Never trust lengths read out of shared memory.
        if cat_len + msg_len > PAYLOAD_CAP {
            return None;
        }
        let cat = std::str::from_utf8(body.get(SLOT_PAYLOAD..SLOT_PAYLOAD + cat_len)?).ok()?;
        let msg = std::str::from_utf8(
            body.get(SLOT_PAYLOAD + cat_len..SLOT_PAYLOAD + cat_len + msg_len)?,
        )
        .ok()?;
        let pid = u32::from_le_bytes(body[SLOT_PID..SLOT_PID + 4].try_into().ok()?);
        Some(Breadcrumb {
            ts_ms: u128::from(ts),
            level,
            category: cat.to_owned(),
            message: msg.to_owned(),
            fields: serde_json::Value::Null,
            pid: Some(pid),
        })
    }

    /// Byte offset of `slot`, or `None` if it does not lie wholly inside the
    /// mapping.
    fn slot_base(&self, slot: u64) -> Option<usize> {
        let base = HEADER.checked_add(usize::try_from(slot).ok()?.checked_mul(SLOT)?)?;
        (base.checked_add(SLOT)? <= self.map.len()).then_some(base)
    }

    /// Copy `bytes` into the mapping at `offset`, one relaxed atomic store each.
    ///
    /// Callers must have proved the range lies inside the mapping (via
    /// [`slot_base`](Self::slot_base)); the debug assertion catches a future
    /// caller that forgets.
    fn write(&self, offset: usize, bytes: &[u8]) {
        debug_assert!(offset + bytes.len() <= self.map.len());
        for (i, byte) in bytes.iter().enumerate() {
            self.cell(offset + i).store(*byte, Ordering::Relaxed);
        }
    }

    /// Copy `out.len()` bytes out of the mapping at `offset`.
    fn read(&self, offset: usize, out: &mut [u8]) {
        debug_assert!(offset + out.len() <= self.map.len());
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.cell(offset + i).load(Ordering::Relaxed);
        }
    }

    /// One byte of the mapping, as an atomic.
    ///
    /// This is the only way payload bytes are touched. `AtomicU8` has no
    /// alignment requirement beyond one byte, so every offset is valid, and
    /// going through it is what makes concurrent access by another process
    /// defined behaviour rather than a data race.
    fn cell(&self, offset: usize) -> &AtomicU8 {
        // SAFETY: `offset` is inside the mapping (checked by every caller's
        // `slot_base`), the mapping outlives `&self`, and `AtomicU8` is
        // 1-aligned so any byte offset is a valid place to put one.
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU8>() }
    }

    fn header(&self, offset: usize) -> &AtomicU64 {
        // SAFETY: the mapping is at least HEADER bytes and page-aligned, so an
        // 8-byte-aligned offset within the header is a valid AtomicU64.
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU64>() }
    }

    /// The sequence number of the slot beginning at `base`.
    ///
    /// Takes an offset rather than a slot index so that it can only be reached
    /// through [`slot_base`](Self::slot_base), which is what proves the slot lies
    /// inside the mapping. Taking an index here is how the bounds check came to
    /// be skipped on the one path that did not go through it.
    fn slot_seq_at(&self, base: usize) -> &AtomicU64 {
        // SAFETY: `base` came from `slot_base`, so `base + SLOT` is within the
        // mapping. HEADER and SLOT are multiples of 8, so `base + SLOT_SEQ` is
        // 8-byte aligned and a valid place for an AtomicU64.
        unsafe { &*self.map.as_ptr().add(base + SLOT_SEQ).cast::<AtomicU64>() }
    }
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 character.
fn clamp_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn level_byte(level: Level) -> u8 {
    match level {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}

fn byte_level(b: u8) -> Level {
    match b {
        0 => Level::Trace,
        1 => Level::Debug,
        3 => Level::Warn,
        4 => Level::Error,
        _ => Level::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let ring = SharedRing::open(tmp.path().join("ring"), 8).unwrap();
        ring.record(Level::Info, "myapp.commit", "committed 9557");
        ring.record(Level::Warn, "myapp.free", "released chain");

        let crumbs = ring.snapshot();
        assert_eq!(crumbs.len(), 2);
        assert_eq!(crumbs[0].category, "myapp.commit");
        assert_eq!(crumbs[0].message, "committed 9557");
        assert_eq!(crumbs[1].level, Level::Warn);
    }

    #[test]
    fn the_ring_is_bounded_and_keeps_the_newest() {
        let tmp = tempfile::tempdir().unwrap();
        let ring = SharedRing::open(tmp.path().join("ring"), 4).unwrap();
        for i in 0..10 {
            ring.record(Level::Info, "t", &format!("m{i}"));
        }
        let crumbs = ring.snapshot();
        assert_eq!(crumbs.len(), 4, "capacity bound holds");
        assert_eq!(crumbs[0].message, "m6");
        assert_eq!(crumbs[3].message, "m9");
    }

    #[test]
    fn a_second_opener_sees_the_first_writers_crumbs() {
        // The whole point: the trail belongs to the artifact, not the process.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");

        let writer = SharedRing::open(&path, 16).unwrap();
        writer.record(Level::Info, "myapp.commit", "wrote page 6050");
        drop(writer);

        // A different "process" opening the same store later.
        let detector = SharedRing::open(&path, 16).unwrap();
        detector.record(Level::Error, "myapp.open", "dangling child detected");

        let crumbs = detector.snapshot();
        assert_eq!(crumbs.len(), 2, "joining a ring must not clear it");
        assert_eq!(crumbs[0].message, "wrote page 6050");
        assert_eq!(crumbs[1].message, "dangling child detected");
    }

    #[test]
    fn a_slot_abandoned_mid_write_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");
        let ring = SharedRing::open(&path, 4).unwrap();
        ring.record(Level::Info, "t", "good");

        // Simulate a process killed between claiming a slot and publishing it:
        // ticket taken, sequence left odd.
        let ticket = ring.header(HDR_TICKET).fetch_add(1, Ordering::AcqRel);
        let base = ring.slot_base(ticket % ring.capacity).unwrap();
        ring.slot_seq_at(base)
            .store((ticket << 1) | 1, Ordering::Release);

        ring.record(Level::Info, "t", "after");

        let crumbs = ring.snapshot();
        let messages: Vec<&str> = crumbs.iter().map(|c| c.message.as_str()).collect();
        assert_eq!(
            messages,
            ["good", "after"],
            "the abandoned slot costs one crumb and nothing else"
        );
    }

    /// Regression: a second opener requesting a different capacity must not
    /// resize the file. Shrinking it would leave the first process's mapping
    /// pointing past EOF, and its next `record` would take SIGBUS — the
    /// recorder killing the process it was monitoring.
    #[test]
    fn joining_with_a_different_capacity_adopts_rather_than_resizes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");

        let first = SharedRing::open(&path, 64).unwrap();
        first.record(Level::Info, "t", "before");
        let size_before = std::fs::metadata(&path).unwrap().len();

        // A second participant that disagrees about capacity.
        let second = SharedRing::open(&path, 4).unwrap();
        assert_eq!(second.capacity(), 64, "the creator's capacity is adopted");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            size_before,
            "the file must not be resized under a live mapping"
        );

        // Both mappings remain usable, and the existing trail is intact.
        second.record(Level::Info, "t", "after");
        first.record(Level::Info, "t", "still alive");
        let messages: Vec<String> = first.snapshot().into_iter().map(|c| c.message).collect();
        assert_eq!(messages, ["before", "after", "still alive"]);
    }

    #[test]
    fn a_garbage_file_is_reinitialized_rather_than_parsed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");
        std::fs::write(&path, vec![0xff; 32]).unwrap();

        let ring = SharedRing::open(&path, 4).unwrap();
        assert!(ring.snapshot().is_empty());
        ring.record(Level::Info, "t", "fresh");
        assert_eq!(ring.snapshot().len(), 1);
    }

    #[test]
    fn oversized_text_is_truncated_on_a_character_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let ring = SharedRing::open(tmp.path().join("ring"), 2).unwrap();
        let long = "é".repeat(500);
        ring.record(Level::Info, "cat", &long);

        let crumbs = ring.snapshot();
        assert_eq!(crumbs.len(), 1, "a huge message still records");
        assert!(crumbs[0].message.len() <= PAYLOAD_CAP);
        assert!(crumbs[0].message.chars().all(|c| c == 'é'));
    }

    /// Regression: `HEADER + capacity * SLOT` used to be computed unchecked.
    /// A capacity that wraps it produced a small file paired with a huge
    /// `capacity` field, and the first `record` wrote far outside the mapping.
    #[test]
    fn an_overflowing_capacity_cannot_size_the_file_out_of_step_with_the_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");

        // The exact shape that wrapped: `capacity * SLOT` overflows `usize`.
        let ring = SharedRing::open(&path, usize::MAX / SLOT + 1).unwrap();

        assert!(ring.capacity() <= MAX_CAPACITY, "capacity is clamped");
        let expected = HEADER + ring.capacity() * SLOT;
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            expected as u64,
            "the file must be exactly as long as the ring believes it is"
        );

        // And the ring still works, rather than writing outside the mapping.
        ring.record(Level::Info, "t", "after the clamp");
        assert_eq!(ring.snapshot().len(), 1);
    }

    #[test]
    fn every_slot_addressed_by_the_ring_lies_inside_the_mapping() {
        let tmp = tempfile::tempdir().unwrap();
        let ring = SharedRing::open(tmp.path().join("ring"), 32).unwrap();
        for slot in 0..ring.capacity as u64 {
            assert!(
                ring.slot_base(slot).is_some(),
                "slot {slot} must be addressable"
            );
        }
        assert!(
            ring.slot_base(ring.capacity).is_none(),
            "one past the end must not be"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_created_ring_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ring");
        let _ring = SharedRing::open(&path, 4).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600,
            "the trail describes what the process was doing; keep it private"
        );
    }

    #[test]
    fn concurrent_writers_do_not_lose_or_tear_slots() {
        let tmp = tempfile::tempdir().unwrap();
        let ring = std::sync::Arc::new(SharedRing::open(tmp.path().join("ring"), 512).unwrap());

        let mut handles = Vec::new();
        for t in 0..8u32 {
            let ring = ring.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..64u32 {
                    ring.record(Level::Info, "t", &format!("{t}-{i}"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let crumbs = ring.snapshot();
        assert_eq!(crumbs.len(), 512, "8 threads x 64 records fills the ring");
        // Every surviving record must be intact, never a mix of two writers.
        for c in &crumbs {
            let (t, i) = c.message.split_once('-').expect("well-formed record");
            assert!(t.parse::<u32>().unwrap() < 8);
            assert!(i.parse::<u32>().unwrap() < 64);
        }
    }
}

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
//! the artifact should be able to write it — give it the same permissions as
//! the store. A hostile writer can garble the trail (it cannot escape the
//! mapping: every read is bounds-checked and every string is validated UTF-8),
//! but a hostile writer with access to the store has better things to corrupt.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::MmapMut;

use crate::breadcrumbs::{Breadcrumb, Level};

/// `"BBXRING1"` — identifies the file and its layout. A file that does not
/// start with this is reinitialized rather than parsed.
const MAGIC: u64 = u64::from_le_bytes(*b"BBXRING1");

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

/// A bounded breadcrumb trail shared by every process that opens the same file.
///
/// Open one per artifact and hand it to [`crate::Config::shared_ring`]; crumbs
/// then go to both the in-process recorder and this ring, and reports carry the
/// merged trail.
pub struct SharedRing {
    map: MmapMut,
    capacity: u64,
}

// The mapping is shared, and every access goes through atomics or through
// bounds-checked byte copies, so concurrent use from several threads (and
// several processes) is exactly what it is built for.
unsafe impl Send for SharedRing {}
unsafe impl Sync for SharedRing {}

impl SharedRing {
    /// Open (creating if absent) the shared ring at `path` with room for
    /// `capacity` breadcrumbs.
    ///
    /// An existing file with a matching magic and capacity is *joined*, keeping
    /// the crumbs already in it — that is the whole point: the trail outlives
    /// any single process. A file with the wrong magic or size is reinitialized.
    pub fn open(path: impl AsRef<Path>, capacity: usize) -> io::Result<SharedRing> {
        let capacity = capacity.max(1);
        let len = HEADER + capacity * SLOT;

        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let existing = file.metadata()?.len();
        if existing != len as u64 {
            file.set_len(len as u64)?;
        }

        // SAFETY: the file is sized above and stays mapped for the lifetime of
        // the returned value. Other processes mutating it concurrently is the
        // intended design, and every access below is atomic or bounds-checked.
        let map = unsafe { MmapMut::map_mut(&file)? };
        let ring = SharedRing {
            map,
            capacity: capacity as u64,
        };

        // Initialize only when the file is new or does not describe the ring we
        // asked for. Joining an existing, matching ring must not clear it.
        let magic_ok = ring.header(HDR_MAGIC).load(Ordering::Acquire) == MAGIC;
        let cap_ok = ring.header(HDR_CAPACITY).load(Ordering::Acquire) == capacity as u64;
        if !magic_ok || !cap_ok || existing != len as u64 {
            ring.header(HDR_TICKET).store(0, Ordering::Release);
            for slot in 0..capacity {
                ring.slot_seq(slot as u64).store(0, Ordering::Release);
            }
            ring.header(HDR_CAPACITY)
                .store(capacity as u64, Ordering::Release);
            ring.header(HDR_MAGIC).store(MAGIC, Ordering::Release);
        }
        Ok(ring)
    }

    /// Append a breadcrumb. Never blocks, never allocates, and silently
    /// truncates text that does not fit a slot.
    pub fn record(&self, level: Level, category: &str, message: &str) {
        // Claim a slot. `fetch_add` is atomic across processes in a shared
        // mapping, so two processes can never claim the same ticket.
        let ticket = self.header(HDR_TICKET).fetch_add(1, Ordering::AcqRel);
        let slot = ticket % self.capacity;

        // Mark the slot in-flight (odd) before touching the body, so a reader —
        // or a reader in another process after we are killed — knows not to
        // trust it.
        let seq = self.slot_seq(slot);
        seq.store((ticket << 1) | 1, Ordering::Release);

        let base = HEADER + (slot as usize) * SLOT;
        let cat = clamp_utf8(category, PAYLOAD_CAP.min(u8::MAX as usize));
        let msg = clamp_utf8(message, PAYLOAD_CAP - cat.len());

        // SAFETY: writing to our own mapping. Offsets are within the slot by
        // construction: cat.len() + msg.len() <= PAYLOAD_CAP.
        let body =
            unsafe { std::slice::from_raw_parts_mut(self.map.as_ptr().cast_mut().add(base), SLOT) };
        body[SLOT_TS..SLOT_TS + 8].copy_from_slice(&(crate::now_ms() as u64).to_le_bytes());
        body[SLOT_LEVEL] = level_byte(level);
        body[SLOT_PID..SLOT_PID + 4].copy_from_slice(&std::process::id().to_le_bytes());
        body[SLOT_CAT_LEN] = cat.len() as u8;
        body[SLOT_MSG_LEN..SLOT_MSG_LEN + 2].copy_from_slice(&(msg.len() as u16).to_le_bytes());
        body[SLOT_PAYLOAD..SLOT_PAYLOAD + cat.len()].copy_from_slice(cat.as_bytes());
        body[SLOT_PAYLOAD + cat.len()..SLOT_PAYLOAD + cat.len() + msg.len()]
            .copy_from_slice(msg.as_bytes());

        // Publish: even sequence means "this slot is complete".
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
            let seq_cell = self.slot_seq(slot);
            let before = seq_cell.load(Ordering::Acquire);
            if before & 1 == 1 {
                continue; // in flight, or abandoned by a dead writer
            }
            let Some(crumb) = self.read_slot(slot) else {
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

    fn read_slot(&self, slot: u64) -> Option<Breadcrumb> {
        let base = HEADER + (slot as usize) * SLOT;
        let body = self.map.get(base..base + SLOT)?;
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

    fn header(&self, offset: usize) -> &AtomicU64 {
        // SAFETY: the mapping is at least HEADER bytes and page-aligned, so an
        // 8-byte-aligned offset within the header is a valid AtomicU64.
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU64>() }
    }

    fn slot_seq(&self, slot: u64) -> &AtomicU64 {
        let offset = HEADER + (slot as usize) * SLOT + SLOT_SEQ;
        // SAFETY: HEADER and SLOT are multiples of 8 and `slot < capacity`, so
        // this is an 8-byte-aligned offset inside the mapping.
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU64>() }
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
        ring.slot_seq(ticket % ring.capacity)
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

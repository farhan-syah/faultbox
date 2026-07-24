// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read the running binary's GNU build-id — the key that lets a report be
//! symbolicated server-side against the release's stored debug info, without
//! ever shipping debug symbols to users.
//!
//! On Linux the id lives in an ELF `PT_NOTE` segment as an `NT_GNU_BUILD_ID`
//! note. We parse only the ELF + program headers + note segments of
//! `/proc/self/exe` (never the whole binary), and fail soft to `None` on any
//! shape we don't recognize. Non-Linux targets return `None` for now.

/// Return the current binary's GNU build-id as lowercase hex, if available.
#[must_use]
pub fn read_self() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::read().map(hex)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn hex(bytes: Vec<u8>) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    const PT_NOTE: u32 = 4;
    const NT_GNU_BUILD_ID: u32 = 3;

    fn u16le(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }
    fn u32le(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn u64le(b: &[u8], o: usize) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[o..o + 8]);
        u64::from_le_bytes(a)
    }

    /// Parse `/proc/self/exe` for the build-id descriptor bytes.
    pub(super) fn read() -> Option<Vec<u8>> {
        let mut f = File::open("/proc/self/exe").ok()?;

        // ELF header (64 bytes for ELF64).
        let mut ehdr = [0u8; 64];
        f.read_exact(&mut ehdr).ok()?;
        if &ehdr[0..4] != b"\x7fELF" {
            return None;
        }
        if ehdr[4] != 2 || ehdr[5] != 1 {
            // Only ELF64 little-endian is handled.
            return None;
        }
        let e_phoff = u64le(&ehdr, 32);
        let e_phentsize = u16le(&ehdr, 54) as usize;
        let e_phnum = u16le(&ehdr, 56) as usize;
        if e_phentsize < 56 || e_phnum == 0 || e_phnum > 1024 {
            return None;
        }

        // Read the whole program-header table.
        let mut ph = vec![0u8; e_phentsize.checked_mul(e_phnum)?];
        f.seek(SeekFrom::Start(e_phoff)).ok()?;
        f.read_exact(&mut ph).ok()?;

        for i in 0..e_phnum {
            let base = i * e_phentsize;
            let p_type = u32le(&ph, base);
            if p_type != PT_NOTE {
                continue;
            }
            let p_offset = u64le(&ph, base + 8);
            let p_filesz = u64le(&ph, base + 32);
            if p_filesz == 0 || p_filesz > (1 << 20) {
                continue;
            }
            let mut notes = vec![0u8; usize::try_from(p_filesz).ok()?];
            f.seek(SeekFrom::Start(p_offset)).ok()?;
            if f.read_exact(&mut notes).is_err() {
                continue;
            }
            if let Some(desc) = scan_notes(&notes) {
                return Some(desc);
            }
        }
        None
    }

    /// Walk a note segment for an `NT_GNU_BUILD_ID` note and return its desc.
    fn scan_notes(notes: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0usize;
        while pos + 12 <= notes.len() {
            let namesz = u32le(notes, pos) as usize;
            let descsz = u32le(notes, pos + 4) as usize;
            let ntype = u32le(notes, pos + 8);
            let name_off = pos + 12;
            let name_end = name_off.checked_add(namesz)?;
            let desc_off = name_end.checked_add((4 - (namesz % 4)) % 4)?; // 4-byte align
            let desc_end = desc_off.checked_add(descsz)?;
            if desc_end > notes.len() {
                break;
            }
            if ntype == NT_GNU_BUILD_ID && &notes[name_off..name_off + namesz] == b"GNU\0" {
                return Some(notes[desc_off..desc_end].to_vec());
            }
            // Advance to the next 4-byte-aligned note.
            pos = desc_end + ((4 - (descsz % 4)) % 4);
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn scan_notes_finds_build_id_among_others() {
            // Craft two notes: a non-GNU note, then an NT_GNU_BUILD_ID note.
            let mut buf = Vec::new();
            // Note 1: name "ABC\0" (4), desc 4 bytes, type 1 (ignored).
            buf.extend_from_slice(&4u32.to_le_bytes());
            buf.extend_from_slice(&4u32.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes());
            buf.extend_from_slice(b"ABC\0");
            buf.extend_from_slice(&[9, 9, 9, 9]);
            // Note 2: name "GNU\0" (4), desc = build id (8 bytes), type 3.
            let id = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
            buf.extend_from_slice(&4u32.to_le_bytes());
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
            buf.extend_from_slice(b"GNU\0");
            buf.extend_from_slice(&id);

            let desc = scan_notes(&buf).expect("build id found");
            assert_eq!(desc, id);
        }

        #[test]
        fn scan_notes_returns_none_when_absent() {
            let mut buf = Vec::new();
            buf.extend_from_slice(&4u32.to_le_bytes());
            buf.extend_from_slice(&2u32.to_le_bytes());
            buf.extend_from_slice(&7u32.to_le_bytes());
            buf.extend_from_slice(b"FOO\0");
            buf.extend_from_slice(&[1, 2, 0, 0]);
            assert!(scan_notes(&buf).is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_self_is_infallible_and_hex_if_present() {
        // On Linux this test binary normally has a build-id; if the toolchain
        // stripped it, we just get None. Either way it must not panic, and any
        // value must be lowercase hex.
        if let Some(id) = read_self() {
            assert!(!id.is_empty());
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
        }
    }
}

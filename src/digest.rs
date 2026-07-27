// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-256, for the digests that travel on a report.
//!
//! An [`Artifact`](crate::report::Artifact) digest makes two claims: that a
//! later occurrence of the same bug is looking at the *same* bad state before
//! it reuses an existing snapshot, and that an analyst can confirm the artifact
//! reached them unaltered. Neither claim survives a non-cryptographic hash — a
//! 64-bit FNV collision is constructible in seconds, which would let a modified
//! artifact pass as the original and let a *differing* store silently reuse an
//! earlier snapshot instead of being preserved.
//!
//! So artifact digests are SHA-256. Grouping fingerprints stay on
//! [`fnv1a`](crate::writer::fnv1a): they only have to be stable and fast, they
//! are explicitly not a security boundary, and changing them would re-key every
//! existing report directory.
//!
//! Implemented in-crate rather than pulled in, because the whole dependency
//! tree of a crash reporter is code that runs inside a failing process, and
//! FIPS 180-4 is 150 lines that never change.

/// Streaming SHA-256 state.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length_bits: u64,
}

/// The 64 round constants: the first 32 bits of the fractional parts of the
/// cube roots of the first 64 primes (FIPS 180-4 §4.2.2).
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// The initial hash value: the first 32 bits of the fractional parts of the
/// square roots of the first 8 primes (FIPS 180-4 §5.3.3).
#[rustfmt::skip]
const INITIAL: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    #[must_use]
    pub fn new() -> Self {
        Sha256 {
            state: INITIAL,
            buffer: [0u8; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    /// Absorb `bytes`.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add((bytes.len() as u64) << 3);

        if self.buffered > 0 {
            let want = 64 - self.buffered;
            let take = want.min(bytes.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&bytes[..take]);
            self.buffered += take;
            bytes = &bytes[take..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }

        let mut chunks = bytes.chunks_exact(64);
        for block in &mut chunks {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
        }
        let rest = chunks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Finish and return the digest as lowercase hex.
    #[must_use]
    pub fn hex(mut self) -> String {
        let length_bits = self.length_bits;

        // FIPS 180-4 padding: a `0x80` byte, zeroes, then the 64-bit length.
        self.absorb_padding(0x80);
        while self.buffered != 56 {
            self.absorb_padding(0x00);
        }
        for b in length_bits.to_be_bytes() {
            self.absorb_padding(b);
        }
        debug_assert_eq!(self.buffered, 0, "the length block completes a block");

        let mut out = String::with_capacity(64);
        for word in self.state {
            for byte in word.to_be_bytes() {
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
        out
    }

    /// Push one padding byte, compressing whenever a block completes. Padding
    /// must not advance the message length, so it bypasses [`update`].
    fn absorb_padding(&mut self, byte: u8) {
        self.buffer[self.buffered] = byte;
        self.buffered += 1;
        if self.buffered == 64 {
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(input: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(input);
        h.hex()
    }

    #[test]
    fn matches_the_fips_180_4_vectors() {
        assert_eq!(
            hex_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn a_million_a_s_matches_the_long_vector() {
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            h.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_in_ragged_chunks_matches_a_single_update() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let once = hex_of(&data);

        // Chunk sizes that straddle the 64-byte block boundary in every way.
        for chunk in [1usize, 7, 63, 64, 65, 127, 128, 333] {
            let mut h = Sha256::new();
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(h.hex(), once, "chunk size {chunk}");
        }
    }

    #[test]
    fn a_message_that_lands_exactly_on_the_padding_boundary_is_correct() {
        // 55 bytes leaves room for the padding byte + length in one block;
        // 56 bytes forces a second block. Both are classic off-by-one sites.
        assert_eq!(
            hex_of(&[b'a'; 55]),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            hex_of(&[b'a'; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex_of(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }
}

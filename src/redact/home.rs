// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replacing the reporting user's home directory — and their username — with a
//! placeholder.
//!
//! A path is diagnostic: which file, how deep, what extension. The username in
//! it is not. Substring replacement gets this half right and half wrong: it is
//! case-sensitive, so a Windows path written `c:\users\ada` slips past a `HOME`
//! of `C:\Users\Ada`; it is separator-sensitive, so `C:/Users/Ada` slips past
//! the same; it has no notion of a path boundary, so a home of `/home/ad`
//! corrupts `/home/adam`; and it only ever sees the home *prefix*, so the
//! username in `/var/log/ada/store.log` is untouched.

use super::edit::{Edit, chain};
use std::borrow::Cow;

/// Usernames too generic to be identifying, and common enough that masking them
/// would strip structure from paths that name no one.
const GENERIC_USERS: &[&str] = &[
    "root",
    "admin",
    "administrator",
    "user",
    "users",
    "home",
    "guest",
    "default",
    "public",
    "ubuntu",
    "debian",
    "docker",
    "runner",
    "jenkins",
    "app",
    "apps",
    "service",
    "services",
    "var",
    "tmp",
];

/// The shortest username worth masking. Below this, the string is too likely to
/// occur inside unrelated path segments to be worth the structural damage.
const MIN_USER_LEN: usize = 3;

/// The reporting user's home directory, and the username derived from it.
pub(super) struct Home {
    dir: String,
    user: Option<String>,
}

impl Home {
    pub(super) fn new(dir: impl Into<String>) -> Self {
        let dir = dir.into();
        let user = dir
            .rsplit(['/', '\\'])
            .find(|segment| !segment.is_empty())
            .filter(|segment| segment.len() >= MIN_USER_LEN)
            .filter(|segment| !GENERIC_USERS.contains(&segment.to_ascii_lowercase().as_str()))
            .map(str::to_owned);
        Home { dir, user }
    }

    pub(super) fn strip<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let stripped = replace_path_prefix(input, &self.dir, "~");
        match &self.user {
            Some(user) => chain(stripped, |text| replace_path_segment(text, user, "~user")),
            None => stripped,
        }
    }
}

/// Replace `needle` wherever it appears as a whole path prefix — matched
/// case-insensitively and treating `/` and `\` as the same separator, because
/// the same directory is spelled several ways on one machine.
fn replace_path_prefix<'a>(input: &'a str, needle: &str, with: &str) -> Cow<'a, str> {
    if needle.is_empty() || input.len() < needle.len() {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut edit = Edit::new(input);
    let mut i = 0;

    while i < bytes.len() {
        if path_matches_at(input, i, needle)
            && starts_on_boundary(bytes, i)
            && ends_on_boundary(bytes, i + needle.len())
        {
            edit.replace(i, i + needle.len(), with);
            i += needle.len();
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
    }
    edit.finish()
}

/// Replace `user` wherever it appears as a complete path segment, so the
/// username survives neither `/var/log/ada/x` nor `C:\Temp\Ada\x`.
fn replace_path_segment<'a>(input: &'a str, user: &str, with: &str) -> Cow<'a, str> {
    let bytes = input.as_bytes();
    let mut edit = Edit::new(input);
    let mut i = 0;

    while i < bytes.len() {
        let segment_start = i + 1;
        let segment_end = segment_start + user.len();
        if is_separator(bytes[i])
            && segment_end <= bytes.len()
            && input.is_char_boundary(segment_start)
            && input.is_char_boundary(segment_end)
            && input[segment_start..segment_end].eq_ignore_ascii_case(user)
            && ends_on_boundary(bytes, segment_end)
        {
            edit.replace(segment_start, segment_end, with);
            i = segment_end;
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
    }
    edit.finish()
}

/// Does `needle` occur at `at`, ignoring case and separator spelling?
fn path_matches_at(input: &str, at: usize, needle: &str) -> bool {
    let hay = input.as_bytes();
    if at + needle.len() > hay.len() {
        return false;
    }
    hay[at..at + needle.len()]
        .iter()
        .zip(needle.as_bytes())
        .all(|(a, b)| (is_separator(*a) && is_separator(*b)) || a.eq_ignore_ascii_case(b))
}

/// A path may only start at the beginning of a token — never in the middle of a
/// longer word.
fn starts_on_boundary(bytes: &[u8], at: usize) -> bool {
    at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'~')
}

/// A path prefix ends where a separator or a non-path character follows, so a
/// home of `/home/ad` does not match inside `/home/adam`.
fn ends_on_boundary(bytes: &[u8], at: usize) -> bool {
    at >= bytes.len() || !(bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'-'))
}

fn is_separator(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_prefix_becomes_a_tilde_and_the_structure_survives() {
        let home = Home::new("/home/ada");
        assert_eq!(
            home.strip("failed to open /home/ada/db/main.db"),
            "failed to open ~/db/main.db"
        );
        assert_eq!(home.strip("/home/ada"), "~");
    }

    #[test]
    fn matching_ignores_case_and_separator_spelling() {
        let home = Home::new("C:\\Users\\Ada");
        assert_eq!(
            home.strip("open c:/users/ada/db/main.db"),
            "open ~/db/main.db"
        );
        assert_eq!(home.strip("open C:\\Users\\Ada\\db"), "open ~\\db");
    }

    #[test]
    fn a_home_that_prefixes_another_users_directory_does_not_corrupt_it() {
        let home = Home::new("/home/ad");
        assert_eq!(home.strip("/home/adam/db"), "/home/adam/db");
        assert_eq!(home.strip("/home/ad/db"), "~/db");
    }

    #[test]
    fn the_username_is_masked_outside_the_home_directory_too() {
        let home = Home::new("/home/ada");
        assert_eq!(
            home.strip("/var/log/ada/store.log"),
            "/var/log/~user/store.log"
        );
        assert_eq!(home.strip("C:\\Temp\\Ada\\x"), "C:\\Temp\\~user\\x");
        // Not a whole segment: this is some other word.
        assert_eq!(home.strip("/var/log/adapters"), "/var/log/adapters");
    }

    #[test]
    fn a_generic_or_short_username_is_not_worth_the_structural_damage() {
        assert_eq!(
            Home::new("/home/root").strip("/var/root/x"),
            "/var/root/x",
            "masking `root` everywhere would strip structure and identify no one"
        );
        assert_eq!(Home::new("/home/ab").strip("/var/ab/x"), "/var/ab/x");
    }

    #[test]
    fn stripping_is_idempotent() {
        let home = Home::new("/home/ada");
        let once = home.strip("/home/ada/db and /var/log/ada/x");
        assert_eq!(home.strip(&once), once);
    }
}

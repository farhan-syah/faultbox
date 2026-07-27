// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building a redacted copy of a string only if there is something to redact.
//!
//! Most strings entering a report carry nothing sensitive, and redaction runs
//! on all of them — every message, every error-chain link, every breadcrumb and
//! every field of every breadcrumb, from inside the panic hook. Copying each
//! one through four passes to discover that four times over is work that buys
//! nothing.
//!
//! So each pass records replacements against the original and allocates only
//! when the first one arrives; a string with nothing to hide comes back
//! borrowed, and the whole chain costs the single allocation the caller needs
//! to return an owned `String`.

use std::borrow::Cow;

pub(super) struct Edit<'a> {
    input: &'a str,
    out: Option<String>,
    copied: usize,
}

impl<'a> Edit<'a> {
    pub(super) fn new(input: &'a str) -> Self {
        Edit {
            input,
            out: None,
            copied: 0,
        }
    }

    /// Replace `input[start..end]`. Spans must arrive in order and must not
    /// overlap — every caller scans left to right, so they do.
    pub(super) fn replace(&mut self, start: usize, end: usize, with: &str) {
        debug_assert!(start >= self.copied, "replacement spans must not overlap");
        // Clamped rather than trusted: a scanner bug must not become a panic
        // inside the panic hook.
        let start = start.max(self.copied);
        let end = end.max(start);
        let capacity = self.input.len();
        let out = self
            .out
            .get_or_insert_with(|| String::with_capacity(capacity));
        out.push_str(&self.input[self.copied..start]);
        out.push_str(with);
        self.copied = end;
    }

    pub(super) fn finish(self) -> Cow<'a, str> {
        match self.out {
            Some(mut out) => {
                out.push_str(&self.input[self.copied..]);
                Cow::Owned(out)
            }
            None => Cow::Borrowed(self.input),
        }
    }
}

/// Apply `pass` to a value that may already have been rewritten, without
/// copying it again when the pass changes nothing.
pub(super) fn chain<'a>(
    value: Cow<'a, str>,
    pass: impl for<'b> Fn(&'b str) -> Cow<'b, str>,
) -> Cow<'a, str> {
    match value {
        Cow::Borrowed(borrowed) => pass(borrowed),
        Cow::Owned(owned) => Cow::Owned(match pass(&owned) {
            // The pass had nothing to change: keep the string we already have.
            Cow::Borrowed(_) => owned,
            Cow::Owned(rewritten) => rewritten,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untouched_string_is_never_copied() {
        let edit = Edit::new("nothing to do here");
        assert!(matches!(edit.finish(), Cow::Borrowed(_)));
    }

    #[test]
    fn replacements_are_stitched_around_the_untouched_text() {
        let mut edit = Edit::new("a SECRET b SECRET c");
        edit.replace(2, 8, "x");
        edit.replace(11, 17, "y");
        assert_eq!(edit.finish(), "a x b y c");
    }

    #[test]
    fn a_replacement_running_to_the_end_needs_no_tail() {
        let mut edit = Edit::new("keep this");
        edit.replace(5, 9, "that");
        assert_eq!(edit.finish(), "keep that");
    }

    #[test]
    fn chaining_reuses_the_string_a_previous_pass_produced() {
        let first = chain(Cow::Borrowed("abc"), |s| Cow::Owned(s.replace('a', "z")));
        let second = chain(first, |_| Cow::Borrowed("unused"));
        assert_eq!(second, "zbc");
    }
}

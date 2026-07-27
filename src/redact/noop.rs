// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redactor that changes nothing.

use super::redactor::Redactor;

/// A redactor that passes everything through unchanged.
///
/// The default, so that a project which has not thought about redaction gets
/// reports that are obviously unsafe to submit rather than reports that look
/// safe and are not.
pub struct NoopRedactor;

impl Redactor for NoopRedactor {
    fn redact(&self, input: &str) -> String {
        input.to_owned()
    }
}

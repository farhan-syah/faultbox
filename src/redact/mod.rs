// SPDX-License-Identifier: MIT OR Apache-2.0

//! Removing user data from every string that enters a report.
//!
//! A report is only submittable if it carries structure and no content. The
//! [`Redactor`] trait is the seam for that; [`BasicRedactor`] is the default
//! implementation, covering the shapes credentials actually arrive in — HTTP
//! header lines, JSON bodies echoed by a client's error string, `Debug` output
//! of a config struct, environment variables, structured breadcrumb fields —
//! rather than the single `key=value` shape that is easiest to scan for.
//!
//! Its failure direction is deliberate: masking a diagnostic field costs a
//! debugging session, masking nothing costs the credential. Where the two
//! conflict, this module over-redacts.

mod assignments;
mod basic;
mod credentials;
mod edit;
mod emails;
mod home;
mod keys;
mod noop;
mod redactor;
mod values;

pub use basic::BasicRedactor;
pub use noop::NoopRedactor;
pub use redactor::{REDACTED, REDACTED_EMAIL, Redactor};

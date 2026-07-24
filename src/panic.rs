// SPDX-License-Identifier: MIT OR Apache-2.0

//! Panic → report bridge.
//!
//! [`install_hook`] chains a `blackbox` capture in front of the previous panic
//! hook: every panic writes a [`crate::report::EventKind::Panic`] report (with
//! the current breadcrumb trail and a backtrace) and then the original hook
//! still runs, so existing behaviour (abort, default message) is preserved.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;

use crate::report::{EventKind, Frame};

/// Convert a captured [`Backtrace`] into report frames. The std backtrace has
/// no stable structured form, so each rendered line becomes a `symbol` frame —
/// enough for a human, and the build-id still enables precise offline
/// symbolication when needed.
pub(crate) fn frames_from_backtrace(bt: &Backtrace) -> Vec<Frame> {
    bt.to_string()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| Frame {
            address: None,
            symbol: Some(line.to_owned()),
            location: None,
        })
        .collect()
}

/// Install the panic hook. Called by [`crate::init`]; idempotent enough that a
/// second install simply re-chains (harmless).
pub(crate) fn install_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        // Best-effort capture; a failure here must never mask the panic itself.
        let message = panic_message(info);
        let bt = Backtrace::force_capture();
        let _ = crate::Capture::new(EventKind::Panic, message)
            .backtrace_frames(frames_from_backtrace(&bt))
            .emit();
        // Preserve prior behaviour (default hook / abort / custom).
        previous(info);
    }));
}

fn panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let body = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".to_owned());
    match info.location() {
        Some(loc) => format!("{body} (at {}:{}:{})", loc.file(), loc.line(), loc.column()),
        None => body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_from_backtrace_yields_symbol_frames() {
        let bt = Backtrace::force_capture();
        let frames = frames_from_backtrace(&bt);
        // With backtraces enabled we get frames; if disabled, empty is fine.
        for f in &frames {
            assert!(f.symbol.is_some());
        }
    }
}

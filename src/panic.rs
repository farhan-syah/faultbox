// SPDX-License-Identifier: MIT OR Apache-2.0

//! Panic → report bridge.
//!
//! The hook installed by [`crate::init`] chains a `faultbox` capture in front
//! of the previous panic hook: every panic writes a
//! [`crate::report::EventKind::Panic`] report (with the current breadcrumb
//! trail and a backtrace) and then the original hook still runs, so existing
//! behaviour (abort, default message) is preserved.

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

thread_local! {
    /// Guards against a panic *inside* the capture path re-entering this hook.
    /// Without it, a panicking redactor or a failing allocation would recurse
    /// until the stack is gone, replacing a diagnosable panic with a stack
    /// overflow — destroying exactly the report we were trying to write.
    static CAPTURING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Install the panic hook. Called by [`crate::init`]; idempotent enough that a
/// second install simply re-chains (harmless).
///
/// The capture is wrapped so that *nothing* it does can mask the original
/// panic: re-entry is refused, and any panic raised while building or writing
/// the report is swallowed. The previous hook always runs, so the process's
/// existing behaviour (default message, abort, a custom hook) is unchanged
/// whether or not the report succeeded.
pub(crate) fn install_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
        let reentered = CAPTURING.with(|c| c.replace(true));
        if !reentered {
            // The capture path allocates, runs adopter-supplied redactor code,
            // and touches the filesystem — all of which can panic.
            let message = panic_message(info);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let bt = Backtrace::force_capture();
                crate::Capture::new(EventKind::Panic, message)
                    .backtrace_frames(frames_from_backtrace(&bt))
                    .emit()
            }));
            CAPTURING.with(|c| c.set(false));
        }
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

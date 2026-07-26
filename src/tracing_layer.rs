// SPDX-License-Identifier: MIT OR Apache-2.0

//! Feed the flight recorder from `tracing` events.
//!
//! The breadcrumb trail is the single most valuable part of a report — it is
//! what turns a non-reproducible failure into a debuggable one. In practice it
//! is also the part most likely to be *empty*, because it depends on adopters
//! remembering to sprinkle [`breadcrumb!`](crate::breadcrumb) calls. A codebase
//! with a handful of manual crumb sites, none of them on the path that actually
//! failed, produces reports with blank trails — which is the common case, not a
//! pathological one.
//!
//! [`BreadcrumbLayer`] removes that dependency on discipline. Add it to an
//! existing `tracing` subscriber stack and every event the project already
//! emits becomes a breadcrumb, so the trail is populated by instrumentation the
//! project was writing anyway:
//!
//! ```no_run
//! use tracing_subscriber::prelude::*;
//!
//! blackbox::init(blackbox::Config::new("myapp", "0.1.0", "/var/lib/myapp/reports"));
//!
//! tracing_subscriber::registry()
//!     // ...alongside whatever layers the project already installs
//!     // (`tracing_subscriber::fmt::layer()`, an EnvFilter, an exporter).
//!     .with(blackbox::BreadcrumbLayer::new().only_targets(["myapp"]))
//!     .init();
//! ```
//!
//! The layer never filters *out* what the subscriber let through beyond its own
//! [`min_level`](BreadcrumbLayer::min_level) and
//! [`only_targets`](BreadcrumbLayer::only_targets) settings, and it does no IO —
//! recording a crumb is a push into a bounded in-memory ring.

use std::fmt::Debug;

use tracing::field::{Field, Visit};
use tracing::{Event, Level as TracingLevel, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::breadcrumbs::{self, Level};

/// A `tracing` layer that records every event it sees as a breadcrumb.
///
/// Cheap by construction: events below [`min_level`](Self::min_level) are
/// rejected before their fields are visited, and a recorded crumb costs one
/// bounded-ring push. Recording is a no-op until [`crate::init`] runs, so
/// installing the layer early is harmless.
pub struct BreadcrumbLayer {
    min_level: TracingLevel,
    only_targets: Vec<String>,
    with_span: bool,
}

impl BreadcrumbLayer {
    /// A layer recording every event at `INFO` or above, from any target.
    #[must_use]
    pub fn new() -> Self {
        BreadcrumbLayer {
            min_level: TracingLevel::INFO,
            only_targets: Vec::new(),
            with_span: true,
        }
    }

    /// Record events at `level` and above. Lowering this to `DEBUG` or `TRACE`
    /// buys a denser trail at the cost of evicting older crumbs sooner — the
    /// ring is bounded, so verbosity trades depth for reach.
    #[must_use]
    pub fn min_level(mut self, level: TracingLevel) -> Self {
        self.min_level = level;
        self
    }

    /// Record only events whose target starts with one of these prefixes, e.g.
    /// `["myapp", "myapp_storage"]`. Empty (the default) accepts every target.
    ///
    /// Worth setting in a binary with chatty dependencies: a bounded ring full
    /// of HTTP client logs has crowded out the storage operations that explain
    /// the corruption.
    #[must_use]
    pub fn only_targets<I, S>(mut self, targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.only_targets = targets.into_iter().map(Into::into).collect();
        self
    }

    /// Attach the enclosing span's name to each crumb (default `true`).
    #[must_use]
    pub fn with_span(mut self, yes: bool) -> Self {
        self.with_span = yes;
        self
    }

    fn accepts(&self, event: &Event<'_>) -> bool {
        let meta = event.metadata();
        if *meta.level() > self.min_level {
            return false;
        }
        if self.only_targets.is_empty() {
            return true;
        }
        self.only_targets
            .iter()
            .any(|t| meta.target().starts_with(t.as_str()))
    }
}

impl Default for BreadcrumbLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for BreadcrumbLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !self.accepts(event) {
            return;
        }
        let meta = event.metadata();

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // `tracing`'s conventional message field becomes the crumb message;
        // everything else stays structured.
        let message = visitor.message.unwrap_or_else(|| meta.name().to_owned());
        let mut fields = visitor.fields;

        if self.with_span
            && let Some(span) = ctx.event_span(event)
        {
            fields.insert(
                "span".to_owned(),
                serde_json::Value::String(span.name().to_owned()),
            );
        }
        if let Some(line) = meta.line() {
            fields.insert("line".to_owned(), serde_json::Value::from(line));
        }

        let fields = if fields.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::Object(fields)
        };

        breadcrumbs::record(level_of(*meta.level()), meta.target(), message, fields);
    }
}

fn level_of(level: TracingLevel) -> Level {
    match level {
        TracingLevel::TRACE => Level::Trace,
        TracingLevel::DEBUG => Level::Debug,
        TracingLevel::INFO => Level::Info,
        TracingLevel::WARN => Level::Warn,
        TracingLevel::ERROR => Level::Error,
    }
}

/// Collects an event's fields into JSON, pulling out the conventional
/// `message` field so it becomes the crumb's human summary.
#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl FieldVisitor {
    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        if field.name() == "message" {
            if let serde_json::Value::String(s) = value {
                self.message = Some(s);
            }
            return;
        }
        self.fields.insert(field.name().to_owned(), value);
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, serde_json::Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, serde_json::Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, serde_json::Value::from(value));
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        // JSON has no i128; render out of range values as text rather than lose
        // them to a lossy cast.
        match i64::try_from(value) {
            Ok(v) => self.insert(field, serde_json::Value::from(v)),
            Err(_) => self.insert(field, serde_json::Value::from(value.to_string())),
        }
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        match u64::try_from(value) {
            Ok(v) => self.insert(field, serde_json::Value::from(v)),
            Err(_) => self.insert(field, serde_json::Value::from(value.to_string())),
        }
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, serde_json::Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, serde_json::Value::from(value));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, serde_json::Value::from(value.to_string()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.insert(field, serde_json::Value::from(format!("{value:?}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    /// Run `body` with a subscriber that has only the breadcrumb layer, and
    /// return the crumbs it produced whose target begins with `tag`.
    ///
    /// The subscriber is scoped rather than global, but the *breadcrumb ring is
    /// process-wide* and these tests run in parallel — so crumbs are selected by
    /// a per-test target tag rather than by position in the ring, which would
    /// race against whatever other tests are recording at the same moment.
    fn crumbs_from(
        tag: &str,
        layer: BreadcrumbLayer,
        body: impl FnOnce(),
    ) -> Vec<breadcrumbs::Breadcrumb> {
        breadcrumbs::init(1024);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, body);
        breadcrumbs::snapshot()
            .into_iter()
            .filter(|c| c.category.starts_with(tag))
            .collect()
    }

    #[test]
    fn events_become_breadcrumbs_with_structured_fields() {
        let crumbs = crumbs_from("t_fields", BreadcrumbLayer::new(), || {
            tracing::info!(target: "t_fields::commit", commit_id = 9558u64, "committed");
        });

        assert_eq!(crumbs.len(), 1);
        let crumb = &crumbs[0];
        assert_eq!(crumb.message, "committed");
        assert_eq!(crumb.category, "t_fields::commit");
        assert_eq!(crumb.level, Level::Info);
        assert_eq!(crumb.fields["commit_id"], 9558);
    }

    #[test]
    fn events_below_min_level_are_dropped() {
        // `tracing`'s Level ordering runs TRACE > DEBUG > INFO > WARN > ERROR,
        // so "WARN and above in severity" is the *less-or-equal* comparison.
        let crumbs = crumbs_from(
            "t_level",
            BreadcrumbLayer::new().min_level(TracingLevel::WARN),
            || {
                tracing::info!(target: "t_level", "chatty");
                tracing::warn!(target: "t_level", "worrying");
                tracing::error!(target: "t_level", "real problem");
            },
        );

        assert_eq!(crumbs.len(), 2, "the info event is dropped");
        assert_eq!(crumbs[0].level, Level::Warn);
        assert_eq!(crumbs[1].message, "real problem");
        assert_eq!(crumbs[1].level, Level::Error);
    }

    #[test]
    fn only_targets_keeps_the_ring_focused_on_our_own_events() {
        let crumbs = crumbs_from(
            "t_target",
            BreadcrumbLayer::new().only_targets(["t_target"]),
            || {
                tracing::info!(target: "hyper::client", "chatty dependency");
                tracing::info!(target: "t_target::pager", "page allocated");
            },
        );

        assert_eq!(crumbs.len(), 1);
        assert_eq!(crumbs[0].category, "t_target::pager");
    }

    #[test]
    fn the_enclosing_span_name_rides_along() {
        let crumbs = crumbs_from("t_span", BreadcrumbLayer::new(), || {
            let span = tracing::info_span!("compaction");
            let _guard = span.enter();
            tracing::info!(target: "t_span", "merging segments");
        });

        assert_eq!(crumbs.len(), 1);
        assert_eq!(crumbs[0].fields["span"], "compaction");
    }
}

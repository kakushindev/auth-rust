use std::sync::Arc;

use ak_axum::error::Result;
use ak_common::mode::Mode;
use axum::{body::Body, extract::State, http::StatusCode, response::Response};
use tokio::task::spawn_blocking;
use tracing::instrument;

use super::{Metrics, go_text};

/// authentik-rs: 2026.2.7's Go `runMetricsServer` `/metrics`: its own
/// registry through `promhttp` (re-rendered by [`go_text`]), followed by the
/// body of Django's `/-/metrics/`.
#[cfg(feature = "core")]
#[instrument(skip_all)]
pub(super) async fn go_metrics_handler(State(state): State<Arc<Metrics>>) -> Result<Response> {
    let gathered = {
        let _scrape = state.promhttp.scrape();
        let mut text = state.prometheus.render();
        text.push_str(&spawn_blocking(go_text::process_text).await?);
        text.push_str(&state.promhttp.text());
        go_text::render(&text)
    };
    let mut body = gathered.into_bytes();
    if let Some(server) = state.server.load_full() {
        body.extend(server.django_metrics().await);
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", go_text::CONTENT_TYPE)
        .body(Body::from(body))?)
}

/// authentik-rs: `http.NotFound` from the metrics mux.
#[cfg(feature = "core")]
pub(super) async fn go_not_found() -> Response {
    let mut response = Response::new(Body::from("404 page not found\n"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

#[instrument(skip_all)]
pub(super) async fn metrics_handler(State(state): State<Arc<Metrics>>) -> Result<Response> {
    let mut metrics = Vec::new();
    state.prometheus.render_to_write(&mut metrics)?;

    #[cfg(feature = "core")]
    if Mode::is_core() {
        match Mode::get() {
            Mode::Server if let Some(server) = state.server.load_full() => {
                server.notify_metrics().await?;
                metrics.extend(spawn_blocking(python::get_python_metrics).await??);
            }
            Mode::Worker if let Some(workers) = state.workers.load_full() => {
                workers.notify_metrics().await?;
                metrics.extend(spawn_blocking(python::get_python_metrics).await??);
            }
            Mode::AllInOne
                if let Some(server) = state.server.load_full()
                    && let Some(workers) = state.workers.load_full() =>
            {
                tokio::try_join!(server.notify_metrics(), workers.notify_metrics())?;
                metrics.extend(spawn_blocking(python::get_python_metrics).await??);
            }
            _ => {}
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=1.0.0; charset=utf-8")
        .body(Body::from(metrics))?)
}

#[cfg(feature = "core")]
mod python {
    use eyre::{Report, Result};
    use pyo3::{
        IntoPyObjectExt as _,
        ffi::c_str,
        prelude::*,
        types::{PyBytes, PyDict},
    };

    pub(super) fn get_python_metrics() -> Result<Vec<u8>> {
        let metrics = Python::attach(|py| {
            let locals = PyDict::new(py);
            Python::run(
                py,
                c_str!(
                    r#"
from prometheus_client import (
    CollectorRegistry,
    generate_latest,
    multiprocess,
)

registry = CollectorRegistry()
multiprocess.MultiProcessCollector(registry)
output = generate_latest(registry)
"#
                ),
                None,
                Some(&locals),
            )?;
            let metrics = locals
                .get_item("output")?
                .unwrap_or(PyBytes::new(py, &[]).into_bound_py_any(py)?)
                .cast::<PyBytes>()
                .map_or_else(|_| PyBytes::new(py, &[]), |v| v.to_owned())
                .as_bytes()
                .to_owned();
            Ok::<_, Report>(metrics)
        })?;
        Ok::<_, Report>(metrics)
    }
}

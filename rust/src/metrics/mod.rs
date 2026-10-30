use std::{env::temp_dir, os::unix, path::PathBuf, sync::Arc};

use ak_axum::{
    router::{make_request_body_limit_layer, wrap_router},
    server,
};
#[cfg(feature = "core")]
use ak_common::Mode;
use ak_common::{
    arbiter::{Arbiter, Tasks},
    config,
};
use arc_swap::ArcSwapOption;
#[cfg(feature = "core")]
use axum::middleware::from_fn;
use axum::{Router, routing::any};
use eyre::Result;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::{
    task::spawn_blocking,
    time::{Duration, interval},
};
use tracing::info;

#[cfg(feature = "core")]
use crate::server::Server;
#[cfg(feature = "core")]
use crate::worker::Workers;

mod go_text;
mod handlers;

pub(crate) fn socket_path() -> PathBuf {
    temp_dir().join("authentik-metrics.sock")
}

pub(crate) struct Metrics {
    prometheus: PrometheusHandle,
    /// authentik-rs: `promhttp.InstrumentMetricHandler`'s collectors.
    promhttp: go_text::PromHttp,
    #[cfg(feature = "core")]
    pub(crate) server: ArcSwapOption<Server>,
    #[cfg(feature = "core")]
    pub(crate) workers: ArcSwapOption<Workers>,
}

impl Metrics {
    fn new() -> Result<Self> {
        info!("installing Prometheus recorder");
        let prometheus = PrometheusBuilder::new()
            .with_recommended_naming(true)
            // authentik-rs: histograms with client_golang's default buckets,
            // as 2026.2.7's Go server exports them.
            .set_buckets(&go_text::GO_DEFAULT_BUCKETS)?
            .install_recorder()?;
        Ok(Self {
            prometheus,
            promhttp: go_text::PromHttp::default(),
            #[cfg(feature = "core")]
            server: ArcSwapOption::empty(),
            #[cfg(feature = "core")]
            workers: ArcSwapOption::empty(),
        })
    }
}

async fn run_upkeep(arbiter: Arbiter, state: Arc<Metrics>) -> Result<()> {
    info!("starting metrics upkeep runner");
    let mut upkeep_interval = interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = upkeep_interval.tick() => {
                let state_clone = Arc::clone(&state);
                spawn_blocking(move || state_clone.prometheus.run_upkeep()).await?;
            },
            () = arbiter.shutdown() => return Ok(())
        }
    }
}

fn build_router(state: Arc<Metrics>) -> Router {
    // authentik-rs: 2026.2.7's Go server serves `/metrics` only, through a
    // bare gorilla mux on `net/http`; other modes keep upstream's router.
    #[cfg(feature = "core")]
    if Mode::get() == Mode::Server {
        return Router::new()
            .route("/metrics", any(handlers::go_metrics_handler))
            .fallback(handlers::go_not_found)
            .with_state(state)
            .layer(from_fn(crate::server::go_compat::mux_clean_path))
            .layer(from_fn(crate::server::go_compat::net_http_framing));
    }
    wrap_router(
        Router::new()
            .fallback(any(handlers::metrics_handler))
            .with_state(state),
        true,
    )
    .layer(make_request_body_limit_layer())
}

pub(crate) fn start(tasks: &mut Tasks) -> Result<Arc<Metrics>> {
    let arbiter = tasks.arbiter();
    let metrics = Arc::new(Metrics::new()?);
    let router = build_router(Arc::clone(&metrics));

    tasks
        .build_task()
        .name(&format!("{}::run_upkeep", module_path!()))
        .spawn(run_upkeep(arbiter, Arc::clone(&metrics)))?;

    for addr in config::get().listen.metrics.iter().copied() {
        server::start_plain(tasks, "metrics", router.clone(), addr)?;
    }

    server::start_unix(
        tasks,
        "metrics",
        router,
        unix::net::SocketAddr::from_pathname(socket_path())?,
    )?;

    Ok(metrics)
}

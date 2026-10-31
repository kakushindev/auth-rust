use std::{
    env::temp_dir,
    os::unix,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ak_axum::{
    extract::{
        host::{Host, host_middleware},
        trusted_proxy::trusted_proxy_middleware,
    },
    router::make_request_body_limit_layer,
};
use ak_common::{Arbiter, Event, Tasks, config, tls::self_signed};
use arc_swap::{ArcSwap, ArcSwapOption};
use argh::FromArgs;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        Method, StatusCode,
        header::{AUTHORIZATION, CONTENT_LENGTH, HOST, USER_AGENT},
    },
    middleware::from_fn,
    response::Response,
    routing::any,
};
use eyre::{Result, eyre};
use hyper_unix_socket::UnixSocketConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use rustls::sign::CertifiedKey;
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    signal::unix::SignalKind,
    sync::Mutex,
    time::{Duration, Instant, interval},
};
use tower::ServiceExt as _;
use tracing::{info, instrument, trace, warn};

use crate::{
    brands::tls::BrandTls,
    outpost::{self, proxy::ProxyOutpost},
    worker::Workers,
};

mod compat;
mod core;
pub(crate) mod go_compat;
mod r#static;
mod tls;

#[derive(Debug, Default, FromArgs, PartialEq, Eq)]
/// Run the authentik server.
#[argh(subcommand, name = "server")]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "argh doesn't support unit structs"
)]
pub(crate) struct Cli {}

pub(super) static GUNICORN_READY: AtomicBool = AtomicBool::new(false);

pub(crate) fn socket_path() -> PathBuf {
    temp_dir().join("authentik.sock")
}

#[derive(Debug)]
pub(crate) struct Server {
    gunicorn: Mutex<Child>,
    socket_path: PathBuf,
    pub(crate) client: Client<UnixSocketConnector<PathBuf>, Body>,
    #[expect(
        dead_code,
        reason = "authentik-rs: 2026.2.7 health routing never consults the workers"
    )]
    pub(crate) workers: ArcSwapOption<Workers>,
    proxy_outpost: Arc<ArcSwapOption<ProxyOutpost>>,
    // authentik-rs: `brand_tls.Watcher` state.
    brand_tls: ArcSwap<BrandTls>,
    fallback_cert: Arc<CertifiedKey>,
    /// authentik-rs: the key Django's `MetricsView` expects (`prepareKeys`).
    metrics_key: Option<String>,
}

/// authentik-rs: `MetricsKeyFile` and `IPCKeyFile` in 2026.2.7's Go
/// `internal/web`.
const METRICS_KEY_FILE: &str = "authentik-core-metrics.key";
pub(super) const IPC_KEY_FILE: &str = "authentik-core-ipc.key";

/// authentik-rs: `prepareKeys`: random keys that Django reads from the temp
/// directory to authenticate the metrics scrape (`MetricsView`) and IPC
/// requests (`token_ipc`, read at import, so before gunicorn starts). Like
/// Go, stops at the first key it cannot write; returns the metrics key.
fn prepare_keys() -> Option<String> {
    fn write_key(name: &str) -> std::io::Result<String> {
        use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

        let mut raw = [0_u8; 64];
        rand::fill(&mut raw);
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(temp_dir().join(name))?
            .write_all(key.as_bytes())?;
        Ok(key)
    }

    let metrics_key = write_key(METRICS_KEY_FILE)
        .inspect_err(|err| warn!(?err, "failed to save metrics key"))
        .ok()?;
    if let Err(err) = write_key(IPC_KEY_FILE) {
        warn!(?err, "failed to save ipc key");
    }
    Some(metrics_key)
}

/// authentik-rs: `os.CreateTemp("", "authentik-gunicorn.*.pid")`: a new
/// empty file named with a random `uint32`, mode 0600.
fn gunicorn_pid_file() -> Option<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;

    for _ in 0_u32..10_000_u32 {
        let path = temp_dir().join(format!("authentik-gunicorn.{}.pid", rand::random::<u32>()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => return Some(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                warn!(?err, "failed to create temporary pid file");
                return None;
            }
        }
    }
    None
}

/// authentik-rs: `Shutdown` removes both key files after stopping gunicorn.
fn remove_keys() {
    if let Err(err) = std::fs::remove_file(temp_dir().join(METRICS_KEY_FILE)) {
        warn!(?err, "failed to remove metrics key file");
    }
    if let Err(err) = std::fs::remove_file(temp_dir().join(IPC_KEY_FILE)) {
        warn!(?err, "failed to remove ipc key file");
    }
}

impl Server {
    fn new(socket_path: PathBuf) -> Result<Self> {
        info!("starting server");
        let metrics_key = prepare_keys();

        // authentik-rs: gounicorn's command line; gunicorn.conf.py binds
        // `$TMPDIR/authentik-core.sock`, and the PID file is
        // `os.CreateTemp("", "authentik-gunicorn.*.pid")`.
        let mut args = vec![
            "-c".to_owned(),
            "./lifecycle/gunicorn.conf.py".to_owned(),
            "authentik.root.asgi:application".to_owned(),
        ];
        if let Some(pid_file) = gunicorn_pid_file() {
            args.extend(["--pid".to_owned(), pid_file.display().to_string()]);
        }
        let gunicorn = Command::new("gunicorn")
            .args(&args)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_mins(1))
            .set_host(false)
            .build(UnixSocketConnector::new(socket_path.clone()));

        Ok(Self {
            gunicorn: Mutex::new(gunicorn),
            client,
            socket_path,
            workers: ArcSwapOption::empty(),
            proxy_outpost: Arc::new(ArcSwapOption::empty()),
            brand_tls: ArcSwap::from_pointee(BrandTls::default()),
            fallback_cert: Arc::new(self_signed::generate_certifiedkey()?),
            metrics_key,
        })
    }

    async fn shutdown(&self, signal: Signal) -> Result<()> {
        trace!(
            signal = signal.as_str(),
            "sending shutdown signal to server"
        );
        let mut gunicorn = self.gunicorn.lock().await;
        if let Some(id) = gunicorn.id() {
            kill(Pid::from_raw(id.cast_signed()), signal)?;
        }
        gunicorn.wait().await?;
        drop(gunicorn);
        remove_keys();
        Ok(())
    }

    async fn graceful_shutdown(&self) -> Result<()> {
        info!("gracefully shutting down server");
        self.shutdown(Signal::SIGTERM).await
    }

    async fn fast_shutdown(&self) -> Result<()> {
        info!("immediately shutting down server");
        self.shutdown(Signal::SIGINT).await
    }

    async fn is_alive(&self) -> bool {
        let try_wait = self.gunicorn.lock().await.try_wait();
        match try_wait {
            Ok(Some(code)) => {
                warn!(?code, "server has exited");
                false
            }
            Ok(None) => true,
            Err(err) => {
                warn!(
                    ?err,
                    "failed to check the status of server process, ignoring"
                );
                true
            }
        }
    }

    async fn is_socket_ready(&self) -> bool {
        let result = UnixStream::connect(&self.socket_path).await;
        trace!(?result, "checking if server socket is ready");
        result.is_ok()
    }

    #[instrument(skip(self))]
    #[expect(dead_code, reason = "authentik-rs: replaced by go_compat::health_live")]
    pub(crate) async fn health_live(&self) -> Result<bool> {
        trace!("sending health live request to server");
        let req = Request::builder()
            .method("GET")
            .uri("http://localhost:8000/-/health/live/")
            .header(HOST, "localhost")
            .body(Body::empty())?;
        Ok(self
            .client
            .request(req)
            .await
            .inspect_err(|err| warn!(?err, "failed to send health live request to server"))?
            .status()
            .is_success())
    }

    #[instrument(skip(self))]
    #[expect(
        dead_code,
        reason = "authentik-rs: 2026.2.7 forwards /-/health/ready/ to Django"
    )]
    pub(crate) async fn health_ready(&self) -> Result<bool> {
        trace!("sending health ready request to server");
        let req = Request::builder()
            .method("GET")
            .uri("http://localhost:8000/-/health/ready/")
            .header(HOST, "localhost")
            .body(Body::empty())?;
        Ok(self
            .client
            .request(req)
            .await
            .inspect_err(|err| warn!(?err, "failed to send health ready request to server"))?
            .status()
            .is_success())
    }

    #[instrument(skip(self))]
    pub(crate) async fn notify_metrics(&self) -> Result<()> {
        trace!("sending metrics request to server");
        let req = Request::builder()
            .method("GET")
            .uri("http://localhost:8000/-/metrics/")
            .header(HOST, "localhost")
            .body(Body::empty())?;
        self.client
            .request(req)
            .await
            .inspect_err(|err| warn!(?err, "failed to send metrics request to server"))?;
        Ok(())
    }

    /// authentik-rs: the Django half of 2026.2.7's `/metrics`: `GET
    /// <web.path>-/metrics/` with the metrics key. Go appends whatever body
    /// comes back, whatever its status; on an error it logs and appends
    /// nothing.
    pub(crate) async fn django_metrics(&self) -> Vec<u8> {
        let fetch = async {
            let req = Request::builder()
                .method("GET")
                .uri(format!(
                    "http://localhost:8000{}-/metrics/",
                    config::get().web.path
                ))
                .header(HOST, "localhost:8000")
                .header(USER_AGENT, "Go-http-client/1.1")
                .header(
                    AUTHORIZATION,
                    format!("Bearer {}", self.metrics_key.as_deref().unwrap_or_default()),
                )
                .body(Body::empty())?;
            let res = self.client.request(req).await?;
            let body = http_body_util::BodyExt::collect(res.into_body()).await?;
            Ok::<_, eyre::Report>(body.to_bytes().to_vec())
        };
        fetch
            .await
            .inspect_err(|err| warn!(?err, "failed to get upstream metrics"))
            .unwrap_or_default()
    }
}

async fn watch_server(arbiter: Arbiter, server: Arc<Server>) -> Result<()> {
    info!("starting server watcher");
    let mut events_rx = arbiter.events_subscribe();
    let mut check_interval = interval(Duration::from_secs(5));
    let mut start_interval = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            event = events_rx.recv() => {
                if let Ok(Event::Signal(signal)) = event
                    && signal == SignalKind::user_defined1()
                    && !GUNICORN_READY.load(Ordering::Relaxed)
                {
                    info!("server notified us ready, marked ready for operation");
                    GUNICORN_READY.store(true, Ordering::Relaxed);
                    arbiter.send_event(Event::GunicornIsReady)?;
                }
            },
            _ = start_interval.tick(), if !GUNICORN_READY.load(Ordering::Relaxed) => {
                if server.is_socket_ready().await {
                    info!("server socket is accepting connections, marked ready for operation");
                    GUNICORN_READY.store(true, Ordering::Relaxed);
                    arbiter.send_event(Event::GunicornIsReady)?;
                }
            },
            _ = check_interval.tick() => {
                if !server.is_alive().await {
                    arbiter.do_fast_shutdown().await;
                    return Err(eyre!("the server has exited unexpectedly"));
                }
            },
            () = arbiter.fast_shutdown() => {
                server.fast_shutdown().await?;
                return Ok(());
            }
            () = arbiter.graceful_shutdown() => {
                server.graceful_shutdown().await?;
                return Ok(());
            }
        }
    }
}

async fn route_core_and_outpost(
    State((core_router, proxy_router, proxy_outpost)): State<(
        Router,
        Router,
        Arc<ArcSwapOption<ProxyOutpost>>,
    )>,
    Host(host): Host,
    mut request: Request,
) -> Response {
    let start = Instant::now();

    // The embedded outpost is only populated once gunicorn is ready, so this is
    // `None` during startup and every request naturally falls through to core.
    let app = proxy_outpost
        .load_full()
        .and_then(|outpost| outpost.app_for_request(&host, request.uri()));

    let (router, dest) = match app {
        Some(app) => {
            // The proxy router reads the resolved application from the request
            // extensions, so we don't look it up a second time.
            request.extensions_mut().insert(app);
            (proxy_router, "embedded_outpost")
        }
        None => (core_router, "core"),
    };

    let is_head = request.method() == Method::HEAD;
    let mut response = router.oneshot(request).await.expect("infallible");
    // authentik-rs: the inner router already stripped a HEAD body to an
    // exact-size empty body; this outer route would turn that into
    // `Content-Length: 0`, which Go never sends for an empty HEAD response.
    if is_head && !response.headers().contains_key(CONTENT_LENGTH) {
        *response.body_mut() = go_compat::unsized_empty_body();
    }
    // authentik-rs: Go only observes outpost and proxied core requests.
    if dest == "embedded_outpost" || response.extensions().get::<go_compat::Observed>().is_some() {
        metrics::histogram!("authentik_main_request_duration", "dest" => dest)
            .record(start.elapsed().as_secs_f64());
    }
    response
}

fn build_router(server: &Arc<Server>) -> Result<Router> {
    let core_router = core::build_router(server)?;
    let proxy_router = outpost::proxy::embedded_router();

    metrics::describe_histogram!(
        "authentik_main_request_duration",
        metrics::Unit::Seconds,
        "API request latencies in seconds"
    );

    // authentik-rs: Go's embedded outpost answers the ping inside the
    // web.path handler, matching the unprefixed path, so it only exists with
    // the default web.path.
    let router = if config::get().outposts.disable_embedded_outpost || config::get().web.path != "/"
    {
        Router::new()
    } else {
        Router::new().route("/outpost.goauthentik.io/ping", any(StatusCode::NO_CONTENT))
    };

    Ok(router
        // authentik-rs: a plain handler fallback; `any(..)` would nest a second
        // top-level route future that re-adds `Content-Length: 0` to HEAD.
        .fallback(route_core_and_outpost)
        .with_state((core_router, proxy_router, Arc::clone(&server.proxy_outpost)))
        .layer(from_fn(host_middleware))
        .layer(from_fn(trusted_proxy_middleware))
        .layer(make_request_body_limit_layer()))
}

pub(crate) async fn start(_cli: Cli, tasks: &mut Tasks) -> Result<Arc<Server>> {
    let arbiter = tasks.arbiter();
    let mut events_rx = arbiter.events_subscribe();

    // authentik-rs: 2026.2.7's `UnixSocketName`.
    let server = Arc::new(Server::new(temp_dir().join("authentik-core.sock"))?);

    tasks
        .build_task()
        .name(&format!("{}::watch_server", module_path!()))
        .spawn(watch_server(arbiter.clone(), Arc::clone(&server)))?;

    let router = build_router(&server)?;

    for addr in config::get().listen.http.iter().copied() {
        ak_axum::server::start_plain(tasks, "server", router.clone(), addr)?;
    }

    // authentik-rs: a TLS configuration per ClientHello, as 2026.2.7's Go
    // server builds it (see `tls`).
    for addr in config::get().listen.https.iter().copied() {
        ak_axum::server::start_tls_per_hello(
            tasks,
            "server",
            router.clone(),
            addr,
            tls::config_for_hello(Arc::clone(&server)),
        )?;
    }
    tasks
        .build_task()
        .name(&format!("{}::tls::watch_tls_config", module_path!()))
        .spawn(tls::watch_tls_config(arbiter.clone(), Arc::clone(&server)))?;

    ak_axum::server::start_unix(
        tasks,
        "server",
        router,
        unix::net::SocketAddr::from_pathname(socket_path())?,
    )?;

    if !config::get().outposts.disable_embedded_outpost {
        info!("waiting for gunicorn to be ready before starting embedded outpost");
        loop {
            tokio::select! {
                event = events_rx.recv() => {
                    if event == Ok(Event::GunicornIsReady) {
                        break;
                    }
                },
                () = arbiter.shutdown() => {
                    warn!("we were told to shutdown before starting the embedded outpost");
                    return Ok(server);
                },
            }
        }

        info!("starting embedded outpost");
        let proxy_outpost = tokio::select! {
            res = outpost::start::<ProxyOutpost>(outpost::proxy::Cli::default(), tasks, None) => res?,
            () = arbiter.shutdown() => {
                warn!("we were told to shutdown before starting the embedded outpost");
                return Ok(server);
            },
        };
        server.proxy_outpost.store(Some(proxy_outpost));
    }

    Ok(server)
}

//! Utilities to run an axum server.

use std::{io, net, os::unix, path::PathBuf};

use ak_common::arbiter::{Arbiter, Tasks};
use axum::{Extension, Router};
use axum_server::{
    Handle,
    accept::DefaultAcceptor,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use eyre::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{info, trace};

use crate::{
    accept::{
        catch_panic::CatchPanicAcceptor,
        go_tcp::{GoTcpAcceptor, TLS_KEEPALIVE_IDLE},
        proxy_protocol::ProxyProtocolAcceptor,
        tls::{ConfigForHello, LazyTlsAcceptor, TlsAcceptor},
    },
    extract::trusted_proxy::TrustedProxy,
};

/// authentik-rs: create a listener the way Go 1.25.5's `net.Listen("tcp", ..)`
/// does in 2026.2.7.
///
/// A wildcard address (`0.0.0.0`, `[::]`) is bound to `[::]` with
/// `IPV6_V6ONLY` cleared, so it accepts IPv4 and IPv6 whatever
/// `net.ipv6.bindv6only` says, unless the kernel has no IPv6, where it falls
/// back to `0.0.0.0` (`favoriteAddrFamily`). `SO_REUSEADDR` is set, and the
/// backlog is `somaxconn`, which the kernel clamps any larger value to.
fn go_listen(addr: net::SocketAddr) -> io::Result<net::TcpListener> {
    let (socket, addr) = if addr.ip().is_unspecified() {
        let dual_stack = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
            .and_then(|socket| socket.set_only_v6(false).map(|()| socket));
        match dual_stack {
            Ok(socket) => (
                socket,
                net::SocketAddr::new(net::Ipv6Addr::UNSPECIFIED.into(), addr.port()),
            ),
            Err(_) => (
                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
                net::SocketAddr::new(net::Ipv4Addr::UNSPECIFIED.into(), addr.port()),
            ),
        }
    } else {
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        if addr.is_ipv6() {
            // setDefaultSockopts clears it for every IPv6 socket and ignores errors.
            let _ = socket.set_only_v6(false);
        }
        (socket, addr)
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(i32::MAX)?;
    Ok(socket.into())
}

async fn run_plain(
    arbiter: Arbiter,
    name: &str,
    router: Router,
    addr: net::SocketAddr,
) -> Result<()> {
    info!(addr = addr.to_string(), "starting {name} server");

    let handle = Handle::new();
    arbiter.add_net_handle(handle.clone()).await;

    // authentik-rs: Go's listen and accept socket options.
    axum_server::from_tcp(go_listen(addr)?)?
        .acceptor(CatchPanicAcceptor::new(
            GoTcpAcceptor::new(
                ProxyProtocolAcceptor::new().acceptor(DefaultAcceptor::new()),
                None,
            ),
            arbiter.clone(),
        ))
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<net::SocketAddr>())
        .await?;

    Ok(())
}

/// Start a plaintext server.
///
/// `name` is only used for observability purposes and should describe which module is starting the
/// server.
pub fn start_plain(
    tasks: &mut Tasks,
    name: &'static str,
    router: Router,
    addr: net::SocketAddr,
) -> Result<()> {
    let arbiter = tasks.arbiter();
    tasks
        .build_task()
        .name(&format!("{}::run_plain({name}, {addr})", module_path!()))
        .spawn(run_plain(arbiter, name, router, addr))?;
    Ok(())
}

struct UnixSocketGuard(PathBuf);

#[expect(clippy::missing_trait_methods, reason = "We don't use pin drop")]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        trace!(path = ?self.0, "removing socket");
        if let Err(err) = std::fs::remove_file(&self.0) {
            trace!(?err, "failed to remove socket, ignoring");
        }
    }
}

pub(crate) async fn run_unix(
    arbiter: Arbiter,
    name: &str,
    router: Router,
    addr: unix::net::SocketAddr,
) -> Result<()> {
    info!(?addr, "starting {name} server");

    let handle = Handle::new();
    arbiter.add_unix_handle(handle.clone()).await;

    let _guard = if let Some(path) = addr.as_pathname() {
        trace!(?addr, "removing socket");
        if let Err(err) = std::fs::remove_file(path) {
            trace!(?err, "failed to remove socket, ignoring");
        }
        Some(UnixSocketGuard(path.to_owned()))
    } else {
        None
    };
    let router = router.layer(Extension(TrustedProxy(true)));

    axum_server::Server::bind(addr.clone())
        .acceptor(CatchPanicAcceptor::new(
            DefaultAcceptor::new(),
            arbiter.clone(),
        ))
        .handle(handle)
        .serve(router.into_make_service())
        .await?;

    Ok(())
}

/// Start a Unix socket server.
///
/// `name` is only used for observability purposes and should describe which module is starting the
/// server.
pub fn start_unix(
    tasks: &mut Tasks,
    name: &'static str,
    router: Router,
    addr: unix::net::SocketAddr,
) -> Result<()> {
    let arbiter = tasks.arbiter();
    tasks
        .build_task()
        .name(&format!("{}::run_unix({name}, {addr:?})", module_path!()))
        .spawn(run_unix(arbiter, name, router, addr))?;
    Ok(())
}

async fn run_tls(
    arbiter: Arbiter,
    name: &str,
    router: Router,
    addr: net::SocketAddr,
    config: RustlsConfig,
) -> Result<()> {
    info!(addr = addr.to_string(), "starting {name} server");

    let handle = Handle::new();
    arbiter.add_net_handle(handle.clone()).await;

    // authentik-rs: Go's listen and accept socket options, with
    // TCPKeepAliveListener's idle time on HTTPS.
    axum_server::from_tcp(go_listen(addr)?)?
        .acceptor(CatchPanicAcceptor::new(
            GoTcpAcceptor::new(
                ProxyProtocolAcceptor::new().acceptor(TlsAcceptor::new(
                    RustlsAcceptor::new(config).acceptor(DefaultAcceptor::new()),
                )),
                Some(TLS_KEEPALIVE_IDLE),
            ),
            arbiter.clone(),
        ))
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<net::SocketAddr>())
        .await?;

    Ok(())
}

/// Start a TLS server.
///
/// `name` is only used for observability purposes and should describe which module is starting the
/// server.
pub fn start_tls(
    tasks: &mut Tasks,
    name: &'static str,
    router: Router,
    addr: net::SocketAddr,
    config: RustlsConfig,
) -> Result<()> {
    let arbiter = tasks.arbiter();
    tasks
        .build_task()
        .name(&format!("{}::run_tls({name}, {addr})", module_path!()))
        .spawn(run_tls(arbiter, name, router, addr, config))?;
    Ok(())
}

/// authentik-rs: [`run_tls`] with the configuration chosen per `ClientHello`
/// (Go's `GetConfigForClient`).
async fn run_tls_per_hello(
    arbiter: Arbiter,
    name: &str,
    router: Router,
    addr: net::SocketAddr,
    config_for_hello: ConfigForHello,
) -> Result<()> {
    info!(addr = addr.to_string(), "starting {name} server");

    let handle = Handle::new();
    arbiter.add_net_handle(handle.clone()).await;

    axum_server::from_tcp(go_listen(addr)?)?
        .acceptor(CatchPanicAcceptor::new(
            GoTcpAcceptor::new(
                ProxyProtocolAcceptor::new().acceptor(LazyTlsAcceptor::new(
                    DefaultAcceptor::new(),
                    config_for_hello,
                )),
                Some(TLS_KEEPALIVE_IDLE),
            ),
            arbiter.clone(),
        ))
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<net::SocketAddr>())
        .await?;

    Ok(())
}

/// authentik-rs: start a TLS server whose configuration is chosen for each
/// connection from its `ClientHello`.
///
/// `name` is only used for observability purposes and should describe which module is starting the
/// server.
pub fn start_tls_per_hello(
    tasks: &mut Tasks,
    name: &'static str,
    router: Router,
    addr: net::SocketAddr,
    config_for_hello: ConfigForHello,
) -> Result<()> {
    let arbiter = tasks.arbiter();
    tasks
        .build_task()
        .name(&format!(
            "{}::run_tls_per_hello({name}, {addr})",
            module_path!()
        ))
        .spawn(run_tls_per_hello(
            arbiter,
            name,
            router,
            addr,
            config_for_hello,
        ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ak_common::config::schema::parse_go_listen_addr;
    use serde_json::Value;
    use socket2::SockRef;

    use super::go_listen;

    /// Replays `tests/differential/listen/main.go`'s record of Go's
    /// `net.Listen("tcp", ..)` through the config parser and [`go_listen`].
    #[test]
    fn go_listen_matches_go() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../testdata/go_listen.json")).expect("valid JSON");
        assert!(!cases.is_empty());
        for case in cases {
            let address = case["address"].as_str().expect("address");
            let listener = parse_go_listen_addr(address)
                .and_then(|addr| go_listen(addr).map_err(|err| err.to_string()));
            if case["error"].as_bool().expect("error") {
                assert!(
                    listener.is_err(),
                    "{address}: Go fails, Rust binds {listener:?}"
                );
                continue;
            }
            let listener =
                listener.unwrap_or_else(|err| panic!("{address}: Go binds, Rust: {err}"));
            let local = listener.local_addr().expect("local addr");
            let family = if local.is_ipv4() { "inet" } else { "inet6" };
            let v6only = local.is_ipv6() && SockRef::from(&listener).only_v6().expect("getsockopt");
            let port = match case["port"].as_i64().expect("port") {
                -1 => {
                    assert_ne!(local.port(), 0, "{address}");
                    i64::from(local.port())
                }
                port => port,
            };
            assert_eq!(
                (
                    family,
                    local.ip().to_string(),
                    i64::from(local.port()),
                    v6only
                ),
                (
                    case["family"].as_str().expect("family"),
                    case["ip"].as_str().expect("ip").to_owned(),
                    port,
                    case["v6only"].as_bool().unwrap_or(false),
                ),
                "{address}"
            );
        }
    }
}

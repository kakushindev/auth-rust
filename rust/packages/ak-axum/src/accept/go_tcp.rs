//! authentik-rs: Go's socket options on accepted connections.
//!
//! Go 1.25.5's `net.TCPListener` (`newTCPConn`) sets them on every
//! connection the 2026.2.7 Go front server accepts.

use std::time::Duration;

use axum_server::accept::Accept;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tracing::warn;

/// Go's `defaultTCPKeepAliveIdle`, `defaultTCPKeepAliveInterval` and
/// `defaultTCPKeepAliveCount`.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_COUNT: u32 = 9;

/// `internal/utils/web.TCPKeepAliveListener`, which wraps the HTTPS listener,
/// calls `SetKeepAlivePeriod(3 * time.Minute)`, changing only the idle time.
pub(crate) const TLS_KEEPALIVE_IDLE: Duration = Duration::from_mins(3);

/// Acceptor setting `TCP_NODELAY` and Go's keep-alive probes, then
/// delegating to the inner acceptor.
#[derive(Clone)]
pub(crate) struct GoTcpAcceptor<A> {
    inner: A,
    keepalive_idle: Option<Duration>,
}

impl<A> GoTcpAcceptor<A> {
    /// `keepalive_idle` overrides the idle time after the defaults are set,
    /// as `TCPKeepAliveListener` does; its errors are logged like Go's.
    pub(crate) fn new(inner: A, keepalive_idle: Option<Duration>) -> Self {
        Self {
            inner,
            keepalive_idle,
        }
    }
}

impl<A, S> Accept<TcpStream, S> for GoTcpAcceptor<A>
where
    A: Accept<TcpStream, S>,
{
    type Future = A::Future;
    type Service = A::Service;
    type Stream = A::Stream;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let socket = SockRef::from(&stream);
        // newTCPConn ignores these errors.
        let _ = socket.set_tcp_nodelay(true);
        let _ = socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(KEEPALIVE_IDLE)
                .with_interval(KEEPALIVE_INTERVAL)
                .with_retries(KEEPALIVE_COUNT),
        );
        if let Some(idle) = self.keepalive_idle {
            if let Err(err) = socket.set_keepalive(true) {
                warn!(?err, "Error setting Keep-Alive");
            }
            if let Err(err) = socket.set_tcp_keepalive(&TcpKeepalive::new().with_time(idle)) {
                warn!(?err, "Error setting Keep-Alive period");
            }
        }
        self.inner.accept(stream, service)
    }
}

#[cfg(test)]
mod tests {
    use axum_server::accept::DefaultAcceptor;
    use tokio::net::TcpListener;

    use super::*;

    /// The options [`GoTcpAcceptor`] sets, read back from the socket.
    fn keepalive_options(stream: &TcpStream) -> (bool, bool, Duration, Duration, u32) {
        let socket = SockRef::from(stream);
        (
            socket.tcp_nodelay().expect("getsockopt"),
            socket.keepalive().expect("getsockopt"),
            socket.tcp_keepalive_time().expect("getsockopt"),
            socket.tcp_keepalive_interval().expect("getsockopt"),
            socket.tcp_keepalive_retries().expect("getsockopt"),
        )
    }

    async fn accepted(keepalive_idle: Option<Duration>) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = TcpStream::connect(addr).await.expect("connect");
        let (stream, _) = listener.accept().await.expect("accept");
        let acceptor = GoTcpAcceptor::new(DefaultAcceptor::new(), keepalive_idle);
        let (stream, ()) = acceptor.accept(stream, ()).await.expect("accept");
        stream
    }

    #[tokio::test]
    async fn plain_defaults() {
        let stream = accepted(None).await;
        assert_eq!(
            keepalive_options(&stream),
            (
                true,
                true,
                KEEPALIVE_IDLE,
                KEEPALIVE_INTERVAL,
                KEEPALIVE_COUNT
            )
        );
    }

    #[tokio::test]
    async fn tls_period() {
        let stream = accepted(Some(TLS_KEEPALIVE_IDLE)).await;
        assert_eq!(
            keepalive_options(&stream),
            (
                true,
                true,
                TLS_KEEPALIVE_IDLE,
                KEEPALIVE_INTERVAL,
                KEEPALIVE_COUNT
            )
        );
    }
}

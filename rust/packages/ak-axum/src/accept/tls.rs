use std::{io, sync::Arc, time::Duration};

use axum::{Extension, middleware::AddExtension};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    time::timeout,
};
use tokio_rustls::{
    LazyConfigAcceptor,
    rustls::{ServerConfig, pki_types::CertificateDer},
    server::TlsStream,
};
use tower::Layer as _;
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct TlsState {
    pub peer_certificates: Option<Vec<CertificateDer<'static>>>,
}

#[derive(Clone)]
pub(crate) struct TlsAcceptor<A> {
    inner: RustlsAcceptor<A>,
}

impl<A> TlsAcceptor<A> {
    pub(crate) fn new(inner: RustlsAcceptor<A>) -> Self {
        Self { inner }
    }
}

impl<A, I, S> Accept<I, S> for TlsAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;
    type Service = AddExtension<A::Service, TlsState>;
    type Stream = TlsStream<A::Stream>;

    #[instrument(skip_all)]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let server_conn = stream.get_ref().1;
            let tls_state = TlsState {
                peer_certificates: server_conn.peer_certificates().map(|c| c.to_owned()),
            };

            let service = Extension(tls_state).layer(service);

            Ok((stream, service))
        })
    }
}

/// authentik-rs: picks the [`ServerConfig`] for each connection from its
/// `ClientHello`, like Go's `tls.Config.GetConfigForClient`. `None` aborts the
/// handshake.
pub type ConfigForHello = Arc<
    dyn Fn(&tokio_rustls::rustls::server::ClientHello<'_>) -> Option<Arc<ServerConfig>>
        + Send
        + Sync,
>;

/// authentik-rs: TLS acceptor with a per-`ClientHello` configuration, wrapping
/// the inner acceptor like [`TlsAcceptor`] and exposing the same [`TlsState`].
#[derive(Clone)]
pub(crate) struct LazyTlsAcceptor<A> {
    inner: A,
    config_for_hello: ConfigForHello,
}

impl<A> LazyTlsAcceptor<A> {
    pub(crate) fn new(inner: A, config_for_hello: ConfigForHello) -> Self {
        Self {
            inner,
            config_for_hello,
        }
    }
}

/// axum-server's `RustlsAcceptor` default, kept for the lazy acceptor.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl<A, I, S> Accept<I, S> for LazyTlsAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;
    type Service = AddExtension<A::Service, TlsState>;
    type Stream = TlsStream<A::Stream>;

    #[instrument(skip_all)]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        let config_for_hello = Arc::clone(&self.config_for_hello);

        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let handshake = async {
                let start = LazyConfigAcceptor::new(
                    tokio_rustls::rustls::server::Acceptor::default(),
                    stream,
                )
                .await?;
                let config = config_for_hello(&start.client_hello()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no TLS configuration for client",
                    )
                })?;
                let mut stream = start.into_stream(config).await?;
                // Go writes its session tickets right after the handshake;
                // rustls queues them until the next write.
                stream.flush().await?;
                Ok::<_, io::Error>(stream)
            };
            let stream = timeout(HANDSHAKE_TIMEOUT, handshake).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
            })??;
            let tls_state = TlsState {
                peer_certificates: stream.get_ref().1.peer_certificates().map(|c| c.to_owned()),
            };

            Ok((stream, Extension(tls_state).layer(service)))
        })
    }
}

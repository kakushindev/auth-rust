use std::sync::{Arc, LazyLock, atomic::Ordering};

use ak_axum::{
    accept::tls::TlsState,
    error::Result,
    extract::{client_ip::ClientIp, host::Host, scheme::Scheme, trusted_proxy::TrustedProxy},
    router::wrap_router,
};
use ak_common::config;
use axum::{
    Extension, Router,
    body::Body,
    extract::{OriginalUri, Request, State},
    http::{
        HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{
            ACCEPT, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, RETRY_AFTER, TRANSFER_ENCODING,
            UPGRADE, X_CONTENT_TYPE_OPTIONS,
        },
    },
    middleware,
    response::{IntoResponse as _, Response},
    routing::any,
};
use http_body_util::BodyExt as _;
use hyper::{body::Incoming, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tracing::{debug, warn};

use crate::server::{GUNICORN_READY, Server, go_compat};

static STARTUP_RESPONSE_JSON: LazyLock<Response<String>> = LazyLock::new(|| {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(RETRY_AFTER, "5")
        .header(CONTENT_TYPE, "application/json")
        .body(
            // authentik-rs: json.Encoder appends a newline.
            format!(
                "{}\n",
                json!({
                    "error": "authentik starting",
                })
            ),
        )
        .expect("infallible")
});

static STARTUP_RESPONSE_HTML: LazyLock<Response<String>> = LazyLock::new(|| {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(CONTENT_TYPE, "text/html")
        .body(include_str!("../../web/dist/standalone/loading/startup.html").to_owned())
        .expect("infallible")
});

static STARTUP_RESPONSE_PLAIN: LazyLock<Response<String>> = LazyLock::new(|| {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(CONTENT_TYPE, "text/plain")
        .body("authentik starting".to_owned())
        .expect("infallible")
});

const X_FORWARDED_CLIENT_CERT: HeaderName = HeaderName::from_static("x-forwarded-client-cert");

fn is_django_http_method(method: &Method) -> bool {
    matches!(
        method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// authentik-rs: net/http `isReplayable`.
fn is_replayable(request: &Request) -> bool {
    let headers = request.headers();
    let empty_body = headers
        .get(CONTENT_LENGTH)
        .is_none_or(|v| v.as_bytes() == b"0")
        && !headers.contains_key(TRANSFER_ENCODING);
    let idempotent = matches!(
        request.method().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE"
    ) || headers.contains_key("idempotency-key")
        || headers.contains_key("x-idempotency-key");
    empty_body && idempotent
}

/// The connection died before a response arrived (closed idle connection).
fn is_stale_connection(err: &hyper_util::client::legacy::Error) -> bool {
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        if let Some(hyper_err) = inner.downcast_ref::<hyper::Error>() {
            return hyper_err.is_incomplete_message()
                || hyper_err.is_canceled()
                || hyper_err.is_closed();
        }
        source = inner.source();
    }
    false
}

/// authentik-rs: `proxyErrorHandler` for a failed upstream request. The
/// error text is Rust's, so it differs from Go's wording.
fn proxy_error_response(accept_header: &str, err: &impl std::fmt::Display) -> Response {
    let message = format!("failed to connect to authentik backend: {err}");
    if accept_header.contains("application/json") {
        (
            StatusCode::BAD_GATEWAY,
            [(CONTENT_TYPE, "application/json")],
            format!("{}\n", json!({ "error": message })),
        )
            .into_response()
    } else {
        (
            StatusCode::BAD_GATEWAY,
            [(CONTENT_TYPE, "text/plain")],
            message,
        )
            .into_response()
    }
}

fn startup_response(accept_header: &str) -> Response {
    let response = if accept_header.contains("application/json") {
        STARTUP_RESPONSE_JSON.clone()
    } else if accept_header.contains("text/html") {
        STARTUP_RESPONSE_HTML.clone()
    } else {
        STARTUP_RESPONSE_PLAIN.clone()
    };

    let (parts, body) = response.into_parts();
    Response::from_parts(parts, body.into())
}

#[expect(
    clippy::too_many_arguments,
    reason = "We need all that data to forward the request properly"
)]
async fn forward_request(
    ClientIp(client_ip): ClientIp,
    Host(host): Host,
    Scheme(scheme): Scheme,
    State(server): State<Arc<Server>>,
    TrustedProxy(trusted_proxy): TrustedProxy,
    tls_state: Option<Extension<TlsState>>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Result<Response> {
    let accept_header = request
        .headers()
        .get(ACCEPT)
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .unwrap_or_default();

    if !GUNICORN_READY.load(Ordering::Relaxed) {
        return Ok(startup_response(&accept_header));
    }
    if !is_django_http_method(request.method()) {
        // authentik-rs: http.Error adds X-Content-Type-Options.
        return Ok((
            StatusCode::NOT_IMPLEMENTED,
            [(X_CONTENT_TYPE_OPTIONS, "nosniff")],
            "Unsupported HTTP method.\n",
        )
            .into_response());
    }

    // authentik-rs: Go observes `authentik_main_request_duration_seconds`
    // only around `rp.ServeHTTP`, so only these responses count.
    let mut response = proxy_to_backend(
        client_ip,
        &host,
        scheme,
        &server,
        trusted_proxy,
        tls_state,
        uri,
        request,
        &accept_header,
    )
    .await
    .into_response();
    response.extensions_mut().insert(go_compat::Observed);
    Ok(response)
}

/// authentik-rs: the part of `forward_request` that 2026.2.7 runs inside
/// `ReverseProxy.ServeHTTP`.
#[expect(
    clippy::too_many_arguments,
    reason = "We need all that data to forward the request properly"
)]
async fn proxy_to_backend(
    client_ip: std::net::IpAddr,
    host: &str,
    scheme: axum::http::uri::Scheme,
    server: &Arc<Server>,
    trusted_proxy: bool,
    tls_state: Option<Extension<TlsState>>,
    uri: Uri,
    mut request: Request,
    accept_header: &str,
) -> Result<Response> {
    let peer = go_compat::peer_addr(&request);
    let uri = Uri::builder()
        .scheme("http")
        .authority("localhost:8000")
        .path_and_query(uri.path_and_query().map(|x| x.as_str()).unwrap_or_default())
        .build()?;
    let request_host = request
        .headers()
        .get(HOST)
        .cloned()
        .or_else(|| HeaderValue::from_str(host).ok());
    *request.uri_mut() = uri;

    // authentik-rs: ReverseProxy notes the requested protocol switch before
    // stripping hop-by-hop headers, and refuses a non-printable one.
    let upgrade = go_compat::upgrade_type(request.headers()).to_vec();
    if !go_compat::is_print(&upgrade) {
        let err = format!(
            "client tried to switch to invalid protocol {}",
            go_compat::go_quote(&upgrade)
        );
        warn!(err, "failed to proxy to backend");
        return Ok(proxy_error_response(accept_header, &err));
    }

    // authentik-rs: the headers Django receives from the 2026.2.7 Go server.
    let method = request.method().clone();
    let forward_host = go_compat::go_forward_headers(
        request.headers_mut(),
        &method,
        peer,
        trusted_proxy,
        tls_state.is_some(),
        request_host,
    );
    if let Some(forward_host) = forward_host {
        request.headers_mut().insert(HOST, forward_host);
    }
    let _ = (client_ip, scheme);

    // authentik-rs: ...and adds the switch back afterwards. Any protocol is
    // proxied, websocket or not, byte for byte (see `upgrade_response`).
    if !upgrade.is_empty() {
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        request
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_bytes(&upgrade)?);
    }
    let client_upgrade = hyper::upgrade::on(&mut request);

    if let Some(tls_state) = tls_state
        && let Some(peer_certificates) = &tls_state.peer_certificates
    {
        let xfcc = peer_certificates
            .iter()
            .map(|cert| {
                let pem_encoded = pem::encode(&pem::Pem::new("CERTIFICATE", cert.as_ref()));
                let url_encoded: String =
                    url::form_urlencoded::byte_serialize(pem_encoded.as_bytes()).collect();
                format!("Cert={url_encoded}")
            })
            .collect::<Vec<_>>()
            .join(",");
        request
            .headers_mut()
            .insert(X_FORWARDED_CLIENT_CERT, HeaderValue::from_str(&xfcc)?);
    }

    // authentik-rs: Go's transport replays a request whose pooled connection
    // was closed under it (gunicorn's 2s keep-alive vs. our idle pool) when
    // the request is replayable: idempotent method or idempotency key, and
    // no body (`isReplayable` in net/http).
    let replay = is_replayable(&request).then(|| {
        let mut retry = Request::builder()
            .method(request.method().clone())
            .uri(request.uri().clone())
            .version(request.version());
        if let Some(headers) = retry.headers_mut() {
            headers.clone_from(request.headers());
        }
        retry
    });
    let mut result = server.client.request(request).await;
    if let (Err(err), Some(retry)) = (&result, replay)
        && is_stale_connection(err)
        && let Ok(retry) = retry.body(Body::empty())
    {
        warn!(?err, "retrying request on a fresh backend connection");
        result = server.client.request(retry).await;
    }

    match result {
        Ok(res) if res.status() == StatusCode::SWITCHING_PROTOCOLS => Ok(upgrade_response(
            res,
            &upgrade,
            client_upgrade,
            accept_header,
        )),
        Ok(res) => {
            let (mut parts, body) = res.into_parts();
            // authentik-rs: ReverseProxy drops hop-by-hop headers and flushes
            // immediately when the upstream length is unknown.
            let flushed = !parts.headers.contains_key(CONTENT_LENGTH);
            go_compat::remove_hop_by_hop(&mut parts.headers);
            parts.extensions.insert(go_compat::Proxied);
            if flushed {
                parts.extensions.insert(go_compat::Flushed);
            }
            Ok(Response::from_parts(
                parts,
                Body::from_stream(body.into_data_stream()),
            ))
        }
        // authentik-rs: proxyErrorHandler answers 502 once the backend runs.
        Err(err) => {
            warn!(?err, "failed to proxy to backend");
            Ok(proxy_error_response(accept_header, &err))
        }
    }
}

/// authentik-rs: `handleUpgradeResponse` in Go 1.25.5's `ReverseProxy`.
///
/// The backend must switch to the protocol the client asked for. The client
/// then gets the backend's 101 with its headers untouched, apart from
/// `ModifyResponse`, and both connections are spliced byte for byte, each
/// side's EOF half-closing the other (`switchProtocolCopier`).
fn upgrade_response(
    mut res: hyper::Response<Incoming>,
    requested: &[u8],
    client_upgrade: OnUpgrade,
    accept_header: &str,
) -> Response {
    let switched = go_compat::upgrade_type(res.headers());
    let err = if !go_compat::is_print(switched) {
        Some(format!(
            "backend tried to switch to invalid protocol {}",
            go_compat::go_quote(switched)
        ))
    } else if !switched.eq_ignore_ascii_case(requested) {
        Some(format!(
            "backend tried to switch protocol {} when {} was requested",
            go_compat::go_quote(switched),
            go_compat::go_quote(requested)
        ))
    } else {
        None
    };
    if let Some(err) = err {
        warn!(err, "failed to proxy to backend");
        return proxy_error_response(accept_header, &err);
    }

    let backend_upgrade = hyper::upgrade::on(&mut res);
    tokio::spawn(async move {
        let (client, backend) = match tokio::try_join!(client_upgrade, backend_upgrade) {
            Ok(upgraded) => upgraded,
            Err(err) => {
                debug!(?err, "protocol switch failed");
                return;
            }
        };
        if let Err(err) =
            tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(backend))
                .await
        {
            debug!(?err, "switched protocol connection closed");
        }
    });

    let (mut parts, _) = res.into_parts();
    parts.extensions.insert(go_compat::Proxied);
    Response::from_parts(parts, Body::empty())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "authentik-rs: upstream's signature; the redirect no longer fails"
)]
pub(super) fn build_router(server: &Arc<Server>) -> eyre::Result<Router> {
    // authentik-rs: the 2026.2.7 Go handler chain (`internal/web`), see
    // `go_compat`. Only `/-/health/live/` is answered locally; every other
    // `/-/` path, including `/-/health/ready/`, goes to Django.
    // gorilla prepends the PathPrefix template to the later Path, so this
    // is `<web.path>-/health/live/`.
    let health_router = Router::new()
        .route("/-/health/live/", any(go_compat::health_live))
        .with_state(Arc::clone(server));
    // Router for endpoints handled in Python
    let gunicorn_router = wrap_router(
        Router::new()
            .fallback(forward_request)
            .with_state(Arc::clone(server)),
        // Enable tracing but only in debug.
        config::get().debug,
    );
    // authentik-rs: natively ported routes take precedence over the
    // gunicorn fallback.
    let compat_router = wrap_router(super::compat::build_router(server), config::get().debug);

    let router = Router::new()
        .merge(health_router)
        .merge(compat_router)
        .merge(gunicorn_router)
        .layer(middleware::from_fn(go_compat::static_dispatch));

    // authentik-rs: with a non-default web.path, gorilla mux only routes `/`
    // (a 302 to web.path) and the web.path prefix; anything else gets
    // `http.NotFound` without the router's middleware.
    let web_path = config::get().web.path.clone();
    let router = if web_path == "/" {
        router
            .layer(middleware::from_fn(go_compat::modify_response))
            .layer(middleware::from_fn(go_compat::gorilla_compress))
    } else {
        let target = web_path.clone();
        Router::new()
            .route(
                "/",
                any(move |method: Method| {
                    let target = target.clone();
                    async move { go_compat::go_redirect(&method, &target, StatusCode::FOUND) }
                }),
            )
            .nest(&web_path, router)
            .layer(middleware::from_fn(go_compat::modify_response))
            .layer(middleware::from_fn(go_compat::gorilla_compress))
            .fallback(go_compat::go_not_found)
    };

    let router = router
        .layer(middleware::from_fn(go_compat::mux_clean_path))
        .layer(middleware::from_fn(go_compat::net_http_framing));

    Ok(router)
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::is_django_http_method;

    #[test]
    fn django_http_methods_are_allowed() {
        for method in [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::TRACE,
        ] {
            assert!(is_django_http_method(&method));
        }
    }

    #[test]
    fn unsupported_http_methods_are_rejected() {
        assert!(!is_django_http_method(&Method::CONNECT));
        assert!(!is_django_http_method(
            &Method::from_bytes(b"PROPFIND").expect("method")
        ));
    }
}

// authentik-rs: replaced by `upgrade_response`, which splices any protocol
// switch like 2026.2.7's ReverseProxy instead of re-framing websockets.
#[expect(dead_code, reason = "authentik-rs: replaced by upgrade_response")]
mod websockets {
    use std::path::Path;

    use ak_axum::error::{AppError, Result};
    use axum::{
        body::Body,
        extract::Request,
        http::{
            HeaderMap, HeaderValue, StatusCode,
            header::{
                CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY,
                SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
            },
        },
        response::{IntoResponse as _, Response},
    };
    use futures::{SinkExt as _, StreamExt as _};
    use hyper::upgrade::OnUpgrade;
    use hyper_util::rt::TokioIo;
    use tokio::{net::UnixStream, sync::mpsc};
    use tokio_tungstenite::{
        WebSocketStream, client_async,
        tungstenite::{
            Error as TungsteniteError, Message, handshake::derive_accept_key, protocol::Role,
        },
    };
    use tracing::{debug, trace, warn};

    pub(super) fn is_websocket_upgrade(headers: &HeaderMap<HeaderValue>) -> bool {
        let has_upgrade = headers
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

        let has_connection = headers
            .get(CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            });

        let has_websocket_key = headers.contains_key(SEC_WEBSOCKET_KEY);
        let has_websocket_version = headers.contains_key(SEC_WEBSOCKET_VERSION);

        has_upgrade && has_connection && has_websocket_key && has_websocket_version
    }

    pub(super) async fn handle_websocket_upgrade(
        mut request: Request,
        socket_path: &Path,
    ) -> Result<Response> {
        let Some(ws_key) = request
            .headers()
            .get(SEC_WEBSOCKET_KEY)
            .and_then(|key| key.to_str().ok())
        else {
            return Ok((StatusCode::BAD_REQUEST, "").into_response());
        };

        let ws_accept = derive_accept_key(ws_key.as_bytes());

        request.headers_mut().remove(SEC_WEBSOCKET_EXTENSIONS);

        let path_q = request
            .uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or_default();
        let uri = format!("ws://localhost:8000{path_q}");

        let mut ws_request =
            tokio_tungstenite::tungstenite::handshake::client::Request::builder().uri(uri);
        for (k, v) in request.headers() {
            ws_request = ws_request.header(k.as_str(), v);
        }
        let ws_request = ws_request.body(())?;

        let stream = UnixStream::connect(socket_path).await?;
        let (upstream_ws, upstream_response) = match client_async(ws_request, stream).await {
            Ok(upstream) => upstream,
            Err(TungsteniteError::Http(upstream_response)) => {
                return Ok((upstream_response.status(), "").into_response());
            }
            Err(err) => return Err(err.into()),
        };

        let mut response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "upgrade")
            .header(SEC_WEBSOCKET_ACCEPT, ws_accept);
        if let Some(selected) = upstream_response.headers().get(SEC_WEBSOCKET_PROTOCOL) {
            response = response.header(SEC_WEBSOCKET_PROTOCOL, selected);
        }
        let response = response.body(Body::empty())?;

        let client_upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            if let Err(err) = handle_websocket_connection(client_upgrade, upstream_ws).await {
                warn!("WebSocket connection error: {}", err.0);
            }
        });

        Ok(response)
    }

    async fn handle_websocket_connection(
        client_upgrade: OnUpgrade,
        upstream_ws: WebSocketStream<UnixStream>,
    ) -> Result<()> {
        let client_ws = WebSocketStream::from_raw_socket(
            TokioIo::new(client_upgrade.await?),
            Role::Server,
            None,
        )
        .await;

        let (mut client_sender, mut client_receiver) = client_ws.split();
        let (mut upstream_sender, mut upstream_receiver) = upstream_ws.split();

        let (close_tx, mut close_rx) = mpsc::channel::<()>(1);
        let close_tx_upstream = close_tx.clone();

        let client_to_upstream = tokio::spawn(async move {
            let mut client_closed = false;
            while let Some(msg) = client_receiver.next().await {
                let msg = msg?;
                match msg {
                    Message::Close(frame) => {
                        if !client_closed {
                            upstream_sender.send(Message::Close(frame)).await?;
                            let _ = close_tx.send(()).await;
                            client_closed = true;
                            break;
                        }
                    }
                    msg @ (Message::Binary(_)
                    | Message::Text(_)
                    | Message::Ping(_)
                    | Message::Pong(_)) => {
                        if !client_closed {
                            upstream_sender.send(msg).await?;
                        }
                    }
                    Message::Frame(_) => {}
                }
            }
            if !client_closed {
                upstream_sender.send(Message::Close(None)).await?;
                let _ = close_tx.send(()).await;
            }
            Ok::<_, AppError>(())
        });

        let upstream_to_client = tokio::spawn(async move {
            let mut upstream_closed = false;
            while let Some(msg) = upstream_receiver.next().await {
                let msg = msg?;
                match msg {
                    Message::Close(frame) => {
                        if !upstream_closed {
                            client_sender.send(Message::Close(frame)).await?;
                            let _ = close_tx_upstream.send(()).await;
                            upstream_closed = true;
                            break;
                        }
                    }
                    msg @ (Message::Binary(_)
                    | Message::Text(_)
                    | Message::Ping(_)
                    | Message::Pong(_)) => {
                        if !upstream_closed {
                            client_sender.send(msg).await?;
                        }
                    }
                    Message::Frame(_) => {}
                }
            }
            if !upstream_closed {
                client_sender.send(Message::Close(None)).await?;
                let _ = close_tx_upstream.send(()).await;
            }
            Ok::<_, AppError>(())
        });

        tokio::select! {
            _ = close_rx.recv() => {
                trace!("WebSocket connection closed gracefully");
            },
            res = client_to_upstream => {
                if let Err(err) = res {
                    debug!("Client to upstream task failed: {:?}", err);
                }
            }
            res = upstream_to_client => {
                if let Err(err) = res {
                    debug!("Upstream to client task failed: {:?}", err);
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use axum::http::header::HOST;
        use tempfile::TempDir;
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            net::UnixListener,
            sync::oneshot,
            time::timeout,
        };
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::handshake::server::{
                ErrorResponse, Request as UpstreamRequest, Response as UpstreamResponse,
            },
        };

        use super::*;

        const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

        /// Stands in for the ASGI application on `socket_path`, answering the
        /// handshake the way uvicorn's wsproto implementation does: it names the
        /// subprotocol the application selected, and accepts `permessage-deflate`
        /// whenever the handshake offers it.
        ///
        /// Resolves to the headers the upstream handshake was made with.
        fn spawn_upstream(
            socket_path: &Path,
            subprotocol: Option<&'static str>,
        ) -> oneshot::Receiver<HeaderMap> {
            let listener = UnixListener::bind(socket_path).expect("failed to bind upstream socket");
            let (headers_tx, headers_rx) = oneshot::channel();

            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("failed to accept");
                #[expect(
                    clippy::result_large_err,
                    reason = "the callback signature is dictated by tungstenite"
                )]
                let callback = |request: &UpstreamRequest, mut response: UpstreamResponse| {
                    let headers = request.headers().clone();
                    if let Some(subprotocol) = subprotocol {
                        response.headers_mut().insert(
                            SEC_WEBSOCKET_PROTOCOL,
                            HeaderValue::from_static(subprotocol),
                        );
                    }
                    if headers.contains_key(SEC_WEBSOCKET_EXTENSIONS) {
                        response.headers_mut().insert(
                            SEC_WEBSOCKET_EXTENSIONS,
                            HeaderValue::from_static("permessage-deflate"),
                        );
                    }
                    drop(headers_tx.send(headers));
                    Ok::<_, ErrorResponse>(response)
                };
                let _upstream = accept_hdr_async(stream, callback)
                    .await
                    .expect("upstream handshake failed");
                // Hold the connection open for the rest of the test.
                std::future::pending::<()>().await;
            });

            headers_rx
        }

        /// Rejects the handshake instead of upgrading, the way the application
        /// answers when a consumer denies the connection.
        fn spawn_rejecting_upstream(socket_path: &Path) {
            let listener = UnixListener::bind(socket_path).expect("failed to bind upstream socket");

            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("failed to accept");
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.expect("failed to read") == 0 {
                        break;
                    }
                    request.extend_from_slice(&byte);
                }
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .expect("failed to write rejection");
            });
        }

        fn client_request(subprotocol: Option<&str>, extensions: Option<&str>) -> Request {
            let mut builder = Request::builder()
                // `forward_request` rewrites the URI before handing the request over.
                .uri("http://localhost:8000/ws/rac/connection-token/")
                .header(HOST, "authentik.company")
                .header(UPGRADE, "websocket")
                .header(CONNECTION, "upgrade")
                .header(SEC_WEBSOCKET_KEY, WS_KEY)
                .header(SEC_WEBSOCKET_VERSION, "13");
            if let Some(subprotocol) = subprotocol {
                builder = builder.header(SEC_WEBSOCKET_PROTOCOL, subprotocol);
            }
            if let Some(extensions) = extensions {
                builder = builder.header(SEC_WEBSOCKET_EXTENSIONS, extensions);
            }
            builder
                .body(Body::empty())
                .expect("failed to build client request")
        }

        /// RAC is the only consumer that negotiates a subprotocol, and browsers
        /// fail a connection when they offered one and the 101 names none.
        #[tokio::test]
        async fn upgrade_echoes_upstream_subprotocol() {
            let dir = TempDir::new().expect("failed to create temp dir");
            let socket_path = dir.path().join("authentik.sock");
            let _upstream = spawn_upstream(&socket_path, Some("guacamole"));

            let response =
                handle_websocket_upgrade(client_request(Some("guacamole"), None), &socket_path)
                    .await
                    .expect("upgrade should succeed");

            assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
            assert_eq!(
                response.headers().get(SEC_WEBSOCKET_PROTOCOL),
                Some(&HeaderValue::from_static("guacamole")),
                "the 101 must name the subprotocol the application selected"
            );
        }

        /// The bridge relays frames unchanged and cannot decode a compressed one,
        /// so the client's extension offer must not reach the application.
        #[tokio::test]
        async fn upgrade_does_not_offer_extensions_upstream() {
            let dir = TempDir::new().expect("failed to create temp dir");
            let socket_path = dir.path().join("authentik.sock");
            let upstream = spawn_upstream(&socket_path, Some("guacamole"));

            let response = handle_websocket_upgrade(
                client_request(
                    Some("guacamole"),
                    Some("permessage-deflate; client_max_window_bits"),
                ),
                &socket_path,
            )
            .await
            .expect("upgrade should succeed");

            assert!(
                !response.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS),
                "the 101 must not name an extension"
            );

            let upstream_headers = timeout(Duration::from_secs(5), upstream)
                .await
                .expect("upstream did not receive a handshake")
                .expect("upstream dropped the handshake");
            assert!(
                !upstream_headers.contains_key(SEC_WEBSOCKET_EXTENSIONS),
                "the upstream handshake must not offer extensions"
            );
        }

        /// Every other consumer accepts without a subprotocol; naming one the
        /// client did not ask for makes browsers drop the connection.
        #[tokio::test]
        async fn upgrade_without_subprotocol_names_none() {
            let dir = TempDir::new().expect("failed to create temp dir");
            let socket_path = dir.path().join("authentik.sock");
            let _upstream = spawn_upstream(&socket_path, None);

            let response = handle_websocket_upgrade(client_request(None, None), &socket_path)
                .await
                .expect("upgrade should succeed");

            assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
            assert!(
                !response.headers().contains_key(SEC_WEBSOCKET_PROTOCOL),
                "the 101 must not name a subprotocol that was not requested"
            );
        }

        /// An application that denies the connection must not be preceded by a
        /// 101 the client would have to tear down immediately.
        #[tokio::test]
        async fn upgrade_propagates_upstream_rejection() {
            let dir = TempDir::new().expect("failed to create temp dir");
            let socket_path = dir.path().join("authentik.sock");
            spawn_rejecting_upstream(&socket_path);

            let response =
                handle_websocket_upgrade(client_request(Some("guacamole"), None), &socket_path)
                    .await
                    .expect("upgrade should return a response");

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
}

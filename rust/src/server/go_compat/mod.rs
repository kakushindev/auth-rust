//! authentik-rs (not part of upstream): HTTP behavior of the authentik
//! 2026.2.7 Go front server (`cmd/server`, `internal/web`) that the Rust
//! server reproduces exactly. "Go" below always means that pinned release
//! and the library versions in its `go.sum` (gorilla/handlers v1.5.2,
//! gorilla/mux, go-http-utils/etag, Go 1.25.5 `net/http`).
//!
//! Layering mirrors the Go handler chain, outermost first:
//! `net_http_framing` (the `net/http` response writer) → `mux_clean_path`
//! (gorilla mux `Router.ServeHTTP`) → `gorilla_compress` (`mainRouter.Use`)
//! → routes.

mod file_server;
mod sniff;

use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_compression::{
    Level,
    tokio::bufread::{DeflateEncoder, GzipEncoder},
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{
            ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST,
            LOCATION, RANGE, SERVER, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, USER_AGENT, VARY,
        },
    },
    middleware::Next,
    response::Response,
};
pub(super) use file_server::static_dispatch;
use futures::{StreamExt as _, TryStreamExt as _, stream};
pub(crate) use sniff::detect_content_type;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::server::Server;

/// `net/http` `bufferBeforeChunkingSize`: a handler that finishes within this
/// many bytes gets a computed `Content-Length`, anything longer is chunked.
const BUFFER_BEFORE_CHUNKING: usize = 2048;

const X_POWERED_BY: HeaderName = HeaderName::from_static("x-powered-by");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

/// Response marker: the body must stream without a computed length. Go's
/// `ReverseProxy` flushes immediately when the upstream length is unknown.
#[derive(Clone, Copy)]
pub(super) struct Flushed;

/// Response marker: the handler replaced `Vary` with `Header().Set`,
/// dropping the `Accept-Encoding` value gorilla added before it ran.
#[derive(Clone, Copy)]
pub(super) struct VaryReplaced;

/// Response marker: the response went through `ReverseProxy.ModifyResponse`,
/// which sets `X-Powered-By: authentik` and deletes `Server`. No other Go
/// response carries `X-Powered-By`.
#[derive(Clone, Copy)]
pub(super) struct Proxied;

/// Request marker: gorilla negotiated this encoding for the response.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
    Gzip,
    Deflate,
}

impl Encoding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }
}

/// `bodyAllowedForStatus`
fn body_allowed(status: StatusCode) -> bool {
    !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED)
}

fn header_str(headers: &HeaderMap, name: &HeaderName) -> String {
    headers
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// An empty body whose size hint is unknown, so axum's top-level route does
/// not derive `Content-Length: 0` from it (Go sends none on an empty HEAD).
pub(super) fn unsized_empty_body() -> Body {
    struct Unsized;
    impl axum::body::HttpBody for Unsized {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::default()
        }

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(None)
        }
    }
    Body::new(Unsized)
}

/// The `net/http` response writer: header suppression for bodiless statuses,
/// automatic `Content-Length` for short bodies, `Content-Type` sniffing.
pub(super) async fn net_http_framing(request: Request, next: Next) -> Response {
    let is_head = request.method() == Method::HEAD;
    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();
    let status = parts.status;

    if !body_allowed(status) {
        // suppressedHeaders: RFC 7232 4.1 for 304, no body otherwise.
        if status == StatusCode::NOT_MODIFIED {
            parts.headers.remove(CONTENT_TYPE);
        }
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        return Response::from_parts(parts, Body::empty());
    }

    let explicit_length = parts.headers.contains_key(CONTENT_LENGTH);
    let flushed = parts.extensions.get::<Flushed>().is_some();

    let mut data = body.into_data_stream();
    let mut buffered = Vec::new();
    let mut complete = true;
    while let Some(chunk) = data.next().await {
        match chunk {
            Ok(chunk) => buffered.extend_from_slice(&chunk),
            Err(err) => {
                tracing::warn!(?err, "failed to read response body");
                break;
            }
        }
        if flushed || buffered.len() > BUFFER_BEFORE_CHUNKING {
            complete = false;
            break;
        }
    }

    let has_ce = parts
        .headers
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !v.is_empty());
    if !has_ce && !parts.headers.contains_key(CONTENT_TYPE) && !buffered.is_empty() {
        let ct = detect_content_type(&buffered);
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static(ct));
    }

    if complete {
        if !explicit_length && (!is_head || !buffered.is_empty()) {
            parts.headers.insert(CONTENT_LENGTH, buffered.len().into());
        } else if is_head && !explicit_length {
            // Go sends no Content-Length for an empty HEAD response; hyper
            // would derive `0` from a body of known size, so hide the size.
            return Response::from_parts(parts, unsized_empty_body());
        }
        return Response::from_parts(parts, Body::from(buffered));
    }

    if !explicit_length {
        parts.headers.remove(CONTENT_LENGTH);
    }
    let head = stream::once(async move { Ok::<_, axum::Error>(Bytes::from(buffered)) });
    Response::from_parts(parts, Body::from_stream(head.chain(data)))
}

/// Go `path.Clean`
pub(super) fn path_clean(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for elem in p.split('/') {
        match elem {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|e| *e != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            e => out.push(e),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// gorilla mux `cleanPath`
fn mux_clean(p: &str) -> String {
    if p.is_empty() {
        return "/".to_owned();
    }
    let p = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };
    let mut np = path_clean(&p);
    if p.ends_with('/') && np != "/" {
        np.push('/');
    }
    np
}

/// Go `url.PathEscape`-style escaping for `encodePath` (`shouldEscape`).
fn escape_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            );
        if keep {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Go's decoded `r.URL.Path`.
pub(super) fn decoded_path(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8_lossy()
        .into_owned()
}

/// gorilla mux redirects requests whose path is not clean before any route
/// or middleware runs (`Router.ServeHTTP`, `skipClean == false`).
pub(super) async fn mux_clean_path(request: Request, next: Next) -> Response {
    let path = decoded_path(request.uri().path());
    let clean = mux_clean(&path);
    if clean == path {
        return next.run(request).await;
    }
    let mut location = escape_path(&clean);
    if let Some(query) = request.uri().query()
        && !query.is_empty()
    {
        location.push('?');
        location.push_str(query);
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

/// gorilla `CompressHandler` as wrapped by authentik's `NewCompressHandler`.
pub(super) async fn gorilla_compress(mut request: Request, next: Next) -> Response {
    let accept = header_str(request.headers(), &ACCEPT_ENCODING);
    let encoding = if header_str(request.headers(), &UPGRADE).is_empty() {
        accept.split(',').map(str::trim).find_map(|e| match e {
            "gzip" => Some(Encoding::Gzip),
            "deflate" => Some(Encoding::Deflate),
            _ => None,
        })
    } else {
        None
    };
    if let Some(enc) = encoding {
        request.headers_mut().remove(ACCEPT_ENCODING);
        request.extensions_mut().insert(enc);
    }

    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();

    // `w.Header().Add("Vary", "Accept-Encoding")` runs before the handler,
    // so it is the first value unless the handler replaced Vary.
    if parts.extensions.get::<VaryReplaced>().is_none() {
        let existing: Vec<HeaderValue> = parts.headers.get_all(VARY).iter().cloned().collect();
        parts.headers.remove(VARY);
        parts
            .headers
            .append(VARY, HeaderValue::from_static("Accept-Encoding"));
        for value in existing {
            parts.headers.append(VARY, value);
        }
    }

    let Some(enc) = encoding else {
        return Response::from_parts(parts, body);
    };
    parts
        .headers
        .insert(CONTENT_ENCODING, HeaderValue::from_static(enc.as_str()));
    parts.headers.remove(CONTENT_LENGTH);

    let mut data = body.into_data_stream();
    let first = loop {
        match data.next().await {
            Some(Ok(chunk)) if chunk.is_empty() => {}
            Some(Ok(chunk)) => break Some(chunk),
            Some(Err(err)) => {
                tracing::warn!(?err, "failed to read response body");
                break None;
            }
            None => break None,
        }
    };
    // compressResponseWriter.Write sniffs a Content-Type when none is set.
    if let Some(chunk) = &first
        && header_str(&parts.headers, &CONTENT_TYPE).is_empty()
    {
        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(detect_content_type(chunk)),
        );
    }

    let input = stream::iter(first.map(Ok::<_, axum::Error>))
        .chain(data)
        .map_err(std::io::Error::other);
    let reader = StreamReader::new(input);
    // gzip.DefaultCompression / flate.DefaultCompression is level 6.
    let body = match enc {
        Encoding::Gzip => Body::from_stream(ReaderStream::new(GzipEncoder::with_quality(
            reader,
            Level::Precise(6),
        ))),
        Encoding::Deflate => Body::from_stream(ReaderStream::new(DeflateEncoder::with_quality(
            reader,
            Level::Precise(6),
        ))),
    };
    Response::from_parts(parts, body)
}

/// Only responses that went through `ReverseProxy.ModifyResponse` carry
/// `X-Powered-By`; that hook also deletes `Server`.
pub(super) async fn modify_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.extensions().get::<Proxied>().is_some() {
        response
            .headers_mut()
            .insert(X_POWERED_BY, HeaderValue::from_static("authentik"));
        response.headers_mut().remove(SERVER);
    } else {
        response.headers_mut().remove(X_POWERED_BY);
    }
    response
}

/// Hop-by-hop headers removed by `httputil.ReverseProxy`.
const HOP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `removeHopByHopHeaders`
pub(super) fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    for name in listed {
        headers.remove(name.as_str());
    }
    for name in HOP_HEADERS {
        headers.remove(name);
    }
}

/// Go `net.SplitHostPort`, host only.
fn split_host(addr: &str) -> Option<String> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return (!port.contains(':')).then(|| host.to_owned());
    }
    let (host, port) = addr.split_once(':')?;
    (!port.contains(':')).then(|| host.to_owned())
}

/// gorilla `getIP`
fn gorilla_get_ip(headers: &HeaderMap) -> Option<String> {
    let xff = header_str(headers, &X_FORWARDED_FOR);
    if !xff.is_empty() {
        return Some(xff.split(", ").next().unwrap_or_default().to_owned());
    }
    let real_ip = header_str(headers, &X_REAL_IP);
    if !real_ip.is_empty() {
        return Some(real_ip);
    }
    let forwarded = header_str(headers, &FORWARDED);
    if forwarded.is_empty() {
        return None;
    }
    // (?i)(?:for=)([^(;|,| )]+)
    let lower = forwarded.to_ascii_lowercase();
    let start = lower.find("for=")? + 4;
    let value: String = forwarded[start..]
        .chars()
        .take_while(|c| !matches!(c, '(' | ';' | '|' | ',' | ' ' | ')'))
        .collect();
    (!value.is_empty()).then(|| value.trim_matches('"').to_owned())
}

/// Go formats the peer of a `0.0.0.0` listener as a plain IPv4 address.
fn go_remote_addr(peer: SocketAddr) -> String {
    match peer.ip().to_canonical() {
        IpAddr::V4(ip) => format!("{ip}:{}", peer.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", peer.port()),
    }
}

/// The request headers Django receives from the Go server: gorilla
/// `ProxyHeaders` (`internal/utils/web/http_forwarded.go`), the `Director`
/// in `internal/web/proxy.go`, `httputil.ReverseProxy` and `http.Transport`.
/// Returns the `Host` header to send.
pub(super) fn go_forward_headers(
    headers: &mut HeaderMap,
    method: &Method,
    peer: Option<SocketAddr>,
    trusted: bool,
    tls: bool,
    request_host: Option<HeaderValue>,
) -> Option<HeaderValue> {
    let mut remote_addr = peer.map(go_remote_addr);
    let mut host = request_host;

    if trusted {
        if let Some(ip) = gorilla_get_ip(headers) {
            remote_addr = Some(ip);
        }
        if let Some(xfh) = headers.get(X_FORWARDED_HOST).filter(|v| !v.is_empty()) {
            host = Some(xfh.clone());
        }
    } else if let Some(remote) = &remote_addr
        && let Some(ip) = split_host(remote)
        && let Ok(value) = HeaderValue::from_str(&ip)
    {
        headers.insert(X_FORWARDED_FOR, value);
    }

    if !trusted {
        headers.remove("ssl-client-cert");
        headers.remove("x-forwarded-tls-client-cert");
        headers.remove("x-forwarded-client-cert");
    }
    if tls {
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
    }

    let te_trailers = headers.get_all(TE).iter().any(|v| {
        String::from_utf8_lossy(v.as_bytes())
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("trailers"))
    });
    remove_hop_by_hop(headers);
    headers.remove(TRAILER);
    if te_trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }

    if let Some(remote) = &remote_addr
        && let Some(ip) = split_host(remote)
    {
        let prior: Vec<String> = headers
            .get_all(X_FORWARDED_FOR)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        let value = if prior.is_empty() {
            ip
        } else {
            format!("{}, {ip}", prior.join(", "))
        };
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(X_FORWARDED_FOR, value);
        }
    }

    // `User-Agent: ""` from the Director makes the transport omit it.
    if headers.get(USER_AGENT).is_some_and(HeaderValue::is_empty) {
        headers.remove(USER_AGENT);
    }
    // http.Transport requests gzip itself unless told otherwise.
    if header_str(headers, &ACCEPT_ENCODING).is_empty()
        && header_str(headers, &RANGE).is_empty()
        && method != Method::HEAD
    {
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    }
    host
}

/// `/-/health/live/` in `internal/web/proxy.go`: probe Django and answer with
/// an empty 200 or 502, independent of the startup state.
pub(super) async fn health_live(State(server): State<Arc<Server>>) -> Response {
    let probe = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:8000/-/health/live/")
        .header(HOST, "localhost:8000")
        .header(USER_AGENT, "goauthentik.io/router/healthcheck")
        .header(ACCEPT_ENCODING, "gzip")
        .body(Body::empty());
    let healthy = match probe {
        Ok(probe) => server
            .client
            .request(probe)
            .await
            .is_ok_and(|res| res.status().is_success()),
        Err(_) => false,
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = if healthy {
        StatusCode::OK
    } else {
        StatusCode::BAD_GATEWAY
    };
    response
}

/// `ConnectInfo` as an optional extension.
pub(super) fn peer_addr(request: &Request) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr)
}

#[cfg(test)]
mod tests {
    use axum::{Router, middleware::from_fn, routing::any};
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn empty_head_has_no_content_length() {
        let inner = Router::new()
            .route("/live", any(async || Response::new(Body::empty())))
            .layer(from_fn(net_http_framing));
        let head = || {
            Request::builder()
                .method(Method::HEAD)
                .uri("/live")
                .body(Body::empty())
                .expect("request")
        };
        let direct = inner.clone().oneshot(head()).await.expect("infallible");
        assert!(!direct.headers().contains_key(CONTENT_LENGTH));

        // Mirrors `server::build_router`: a handler fallback forwarding to the
        // core router, then hiding the stripped body's size.
        let outer = Router::new().fallback(move |request: Request| {
            let inner = inner.clone();
            async move {
                let mut response = inner.oneshot(request).await.expect("infallible");
                if !response.headers().contains_key(CONTENT_LENGTH) {
                    *response.body_mut() = unsized_empty_body();
                }
                response
            }
        });
        let nested = outer.oneshot(head()).await.expect("infallible");
        assert!(!nested.headers().contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn path_clean_matches_go() {
        for (input, want) in [
            ("", "."),
            ("/", "/"),
            ("//a//b/", "/a/b"),
            ("/a/./b/../c", "/a/c"),
            ("/../a", "/a"),
            ("a/../../b", "../b"),
        ] {
            assert_eq!(path_clean(input), want, "{input}");
        }
        assert_eq!(mux_clean("/static//dist/"), "/static/dist/");
        assert_eq!(mux_clean("/a/../b"), "/b");
        assert_eq!(escape_path("/a b/(x)"), "/a%20b/%28x%29");
    }

    #[test]
    fn forwarded_headers_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("6.6.6.6"));
        headers.insert("x-forwarded-client-cert", HeaderValue::from_static("x"));
        let peer: SocketAddr = "[::ffff:192.0.2.1]:4000".parse().expect("addr");
        go_forward_headers(&mut headers, &Method::GET, Some(peer), false, false, None);
        assert_eq!(headers[X_FORWARDED_FOR], "192.0.2.1, 192.0.2.1");
        assert!(!headers.contains_key("x-forwarded-client-cert"));
        assert_eq!(headers[ACCEPT_ENCODING], "gzip");
    }

    #[test]
    fn forwarded_headers_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        headers.insert(X_FORWARDED_HOST, HeaderValue::from_static("other.test"));
        let peer: SocketAddr = "172.18.0.1:4000".parse().expect("addr");
        let host = go_forward_headers(&mut headers, &Method::GET, Some(peer), true, false, None);
        assert_eq!(headers[X_FORWARDED_FOR], "1.1.1.1, 2.2.2.2");
        assert_eq!(host, Some(HeaderValue::from_static("other.test")));

        let mut headers = HeaderMap::new();
        go_forward_headers(&mut headers, &Method::HEAD, Some(peer), true, false, None);
        assert_eq!(headers[X_FORWARDED_FOR], "172.18.0.1");
        assert!(!headers.contains_key(ACCEPT_ENCODING));
    }
}

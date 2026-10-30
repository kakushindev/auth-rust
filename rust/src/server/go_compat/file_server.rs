//! The 2026.2.7 static stack, faithfully: `internal/web/static.go`
//! (`staticHeaderMiddleware`, `DisableIndex`, the path strippers, storage
//! tokens), go-http-utils `etag.Handler` + `fresh.IsFresh`, and Go 1.25.5
//! `http.FileServer` (`net/http/fs.go`).
//!
//! Go's `etag.Handler` buffers the whole response before deciding, so the
//! handlers here write into [`GoWriter`], a buffered `http.ResponseWriter`.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::Request,
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{
            ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
            CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, IF_MATCH, IF_MODIFIED_SINCE,
            IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED, LOCATION, RANGE, VARY,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::Response,
};
use sha1::{Digest as _, Sha1};

use super::{
    Encoding, VaryReplaced, decoded_path, path_clean,
    sniff::{detect_content_type, extension, type_by_extension},
};

/// What a static route serves.
#[derive(Clone)]
pub(in crate::server) enum StaticTarget {
    /// `http.FileServer(http.Dir(root))` behind `StripPrefix(strip)`.
    Dir { root: PathBuf, strip: String },
    /// A `/files/<usage>/` storage backend, guarded by a signed token.
    Storage {
        usage: &'static str,
        root: PathBuf,
        strip: String,
        csp: bool,
    },
    /// A fixed `text/plain` document (`robots.txt`, `security.txt`).
    Text(&'static str),
}

/// The static routes of `configureStatic`, matched in registration order
/// against the decoded path like gorilla `PathPrefix` (`{slug}` = `[^/]+`).
fn match_static(path: &str) -> Option<StaticTarget> {
    let dist = || PathBuf::from("./web/dist");
    let dir = |root: PathBuf, strip: &str| {
        Some(StaticTarget::Dir {
            root,
            strip: strip.to_owned(),
        })
    };
    let slug_assets = |prefix: &str| -> Option<String> {
        let rest = path.strip_prefix(prefix)?;
        let (slug, after) = rest.split_once('/')?;
        (!slug.is_empty() && format!("/{after}").starts_with("/assets"))
            .then(|| format!("{prefix}{slug}"))
    };
    if path.starts_with("/static/dist/") {
        return dir(dist(), "/static/dist/");
    }
    if path.starts_with("/static/authentik/") {
        return dir(PathBuf::from("./web/authentik"), "/static/authentik/");
    }
    if let Some(strip) = slug_assets("/if/flow/") {
        return dir(dist(), &strip);
    }
    if path.starts_with("/if/admin/assets") {
        return dir(dist(), "/if/admin");
    }
    if path.starts_with("/if/user/assets") {
        return dir(dist(), "/if/user");
    }
    if let Some(strip) = slug_assets("/if/rac/") {
        return dir(dist(), &strip);
    }
    let roots = crate::server::r#static::storage_roots();
    for (usage, root, csp) in [
        ("media", roots.media, true),
        ("reports", roots.reports, false),
    ] {
        let strip = format!("/files/{usage}/");
        if let Some(root) = root
            && path.starts_with(&strip)
        {
            return Some(StaticTarget::Storage {
                usage,
                root,
                strip,
                csp,
            });
        }
    }
    match path {
        "/robots.txt" => Some(StaticTarget::Text(include_str!("../../../web/robots.txt"))),
        "/.well-known/security.txt" => Some(StaticTarget::Text(include_str!(
            "../../../web/security.txt"
        ))),
        _ => None,
    }
}

/// The static subrouter is registered first in Go, so it wins over the
/// health route and the reverse proxy.
pub(in crate::server) async fn static_dispatch(
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    match match_static(&decoded_path(request.uri().path())) {
        Some(target) => serve_static(target, request).await,
        None => next.run(request).await,
    }
}

/// A buffered `http.ResponseWriter` (`hashWriter`).
struct GoWriter {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl GoWriter {
    fn write_header(&mut self, code: StatusCode) {
        self.status = code.as_u16();
    }

    fn write(&mut self, data: &[u8]) {
        if self.status == 0 {
            self.status = 200;
        }
        self.body.extend_from_slice(data);
    }

    /// `http.Error`
    fn error(&mut self, text: &str, code: StatusCode) {
        self.headers.remove(CONTENT_LENGTH);
        self.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        self.headers
            .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        self.write_header(code);
        self.write(format!("{text}\n").as_bytes());
    }

    /// `serveError` (Go 1.23+ default: drop caching headers first).
    fn serve_error(&mut self, text: &str, code: StatusCode) {
        for name in [CACHE_CONTROL, CONTENT_ENCODING, ETAG, LAST_MODIFIED] {
            self.headers.remove(name);
        }
        self.error(text, code);
    }

    /// `localRedirect`
    fn local_redirect(&mut self, new_path: &str, raw_query: Option<&str>) {
        let mut location = new_path.to_owned();
        if let Some(q) = raw_query.filter(|q| !q.is_empty()) {
            location.push('?');
            location.push_str(q);
        }
        if let Ok(value) = HeaderValue::from_str(&location) {
            self.headers.insert(LOCATION, value);
        }
        self.write_header(StatusCode::MOVED_PERMANENTLY);
    }

    /// `writeNotModified` (Content-Encoding is restored by authentik's
    /// compressedResponseWriter, so it is left alone here).
    fn write_not_modified(&mut self) {
        self.headers.remove(CONTENT_TYPE);
        self.headers.remove(CONTENT_LENGTH);
        if self.headers.get(ETAG).is_some_and(|v| !v.is_empty()) {
            self.headers.remove(LAST_MODIFIED);
        }
        self.write_header(StatusCode::NOT_MODIFIED);
    }
}

/// The parts of `*http.Request` the static handlers read.
struct GoRequest<'a> {
    method: &'a Method,
    headers: &'a HeaderMap,
    raw_query: Option<&'a str>,
    encoding: Option<Encoding>,
}

impl GoRequest<'_> {
    fn header(&self, name: &axum::http::HeaderName) -> String {
        self.headers
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default()
    }

    fn is_get_or_head(&self) -> bool {
        self.method == Method::GET || self.method == Method::HEAD
    }
}

/// Entry point for every static route.
pub(in crate::server) async fn serve_static(target: StaticTarget, request: Request) -> Response {
    let path = decoded_path(request.uri().path());
    let req = GoRequest {
        method: request.method(),
        headers: request.headers(),
        raw_query: request.uri().query(),
        encoding: request.extensions().get::<Encoding>().copied(),
    };

    let mut w = GoWriter {
        status: 0,
        headers: HeaderMap::new(),
        body: Vec::new(),
    };
    // staticHeaderMiddleware
    w.headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, no-transform"),
    );
    w.headers.insert(
        "x-authentik-version",
        HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    w.headers
        .insert(VARY, HeaderValue::from_static("X-authentik-version, Etag"));

    // DisableIndex
    if path.ends_with('/') {
        w.error("404 page not found", StatusCode::NOT_FOUND);
    } else {
        match &target {
            StaticTarget::Text(text) => {
                w.headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                w.write_header(StatusCode::OK);
                w.write(text.as_bytes());
            }
            StaticTarget::Dir { root, strip } => match path.strip_prefix(strip.as_str()) {
                Some(upath) => file_server(&mut w, &req, root, upath).await,
                None => w.error("404 page not found", StatusCode::NOT_FOUND),
            },
            StaticTarget::Storage {
                usage,
                root,
                strip,
                csp,
            } => match path.strip_prefix(strip.as_str()) {
                Some(upath)
                    if crate::server::r#static::is_storage_token_valid_for_path(
                        usage, upath, &request,
                    ) =>
                {
                    if *csp {
                        w.headers.insert(
                            CONTENT_SECURITY_POLICY,
                            HeaderValue::from_static(
                                "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                            ),
                        );
                    }
                    file_server(&mut w, &req, root, upath).await;
                }
                _ => w.error("404 page not found", StatusCode::NOT_FOUND),
            },
        }
    }

    finish_etag(w, &req)
}

/// go-http-utils `etag.Handler` (strong tags) after the inner handler ran.
fn finish_etag(mut w: GoWriter, req: &GoRequest<'_>) -> Response {
    let status = w.status;
    let has_etag = w.headers.get(ETAG).is_some_and(|v| !v.is_empty());
    if !(has_etag || !(200..300).contains(&status) || status == 204 || w.body.is_empty()) {
        let etag = format!("{}-{}", w.body.len(), hex::encode(Sha1::digest(&w.body)));
        if let Ok(value) = HeaderValue::from_str(&etag) {
            w.headers.insert(ETAG, value);
        }
        if is_fresh(req.headers, &w.headers) {
            w.status = 304;
            w.body.clear();
        }
    }

    let mut response = Response::new(Body::from(w.body));
    *response.status_mut() = StatusCode::from_u16(w.status).unwrap_or(StatusCode::OK);
    *response.headers_mut() = w.headers;
    response.extensions_mut().insert(VaryReplaced);
    response
}

/// `time.Parse(http.TimeFormat, s)`
fn parse_time_format(s: &str) -> Option<SystemTime> {
    let t = httpdate::parse_http_date(s).ok()?;
    (httpdate::fmt_http_date(t) == s).then_some(t)
}

/// go-http-utils `fresh.IsFresh`, including its inverted `If-Match` /
/// `If-Unmodified-Since` handling.
fn is_fresh(req: &HeaderMap, res: &HeaderMap) -> bool {
    let get = |h: &HeaderMap, name: &axum::http::HeaderName| {
        h.get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default()
    };
    let if_modified_since = get(req, &IF_MODIFIED_SINCE);
    let if_unmodified_since = get(req, &IF_UNMODIFIED_SINCE);
    let if_none_match = get(req, &IF_NONE_MATCH);
    let if_match = get(req, &IF_MATCH);
    let cache_control = get(req, &CACHE_CONTROL);
    let etag = get(res, &ETAG);
    let last_modified = get(res, &LAST_MODIFIED);

    if if_modified_since.is_empty()
        && if_unmodified_since.is_empty()
        && if_none_match.is_empty()
        && if_match.is_empty()
    {
        return false;
    }
    if cache_control.contains("no-cache") {
        return false;
    }

    let tags = |s: &str| {
        s.split(',')
            .map(|t| t.trim().to_owned())
            .collect::<Vec<_>>()
    };
    let mut etag_matched = false;
    let mut modified_matched = false;
    if !etag.is_empty() && !if_none_match.is_empty() {
        etag_matched = tags(&if_none_match)
            .iter()
            .any(|t| t == "*" || *t == etag || *t == format!("W/{etag}"));
    }
    if !etag.is_empty() && !if_match.is_empty() && !etag_matched {
        etag_matched = !tags(&if_match).iter().any(|t| {
            t == "*"
                || if t.starts_with("W/") {
                    *t == format!("W/{etag}")
                } else {
                    *t == etag
                }
        });
    }
    let pair = |a: &str, b: &str| Some((parse_time_format(a)?, parse_time_format(b)?));
    if !last_modified.is_empty()
        && !if_modified_since.is_empty()
        && let Some((lm, ims)) = pair(&last_modified, &if_modified_since)
    {
        modified_matched = lm < ims;
    }
    if !last_modified.is_empty()
        && !if_unmodified_since.is_empty()
        && !modified_matched
        && let Some((lm, ius)) = pair(&last_modified, &if_unmodified_since)
    {
        modified_matched = lm > ius;
    }
    etag_matched || modified_matched
}

/// `fileHandler.ServeHTTP` for a path already stripped of its prefix.
async fn file_server(w: &mut GoWriter, req: &GoRequest<'_>, root: &Path, upath: &str) {
    let url_path = if upath.starts_with('/') {
        upath.to_owned()
    } else {
        format!("/{upath}")
    };
    let name = path_clean(&url_path);
    serve_file(w, req, root, &name, &url_path).await;
}

/// Go `path.Base`
fn path_base(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}

enum OpenError {
    NotFound,
    Forbidden,
    Other,
}

/// `http.Dir.Open` + `Stat` + `toHTTPError`/`mapOpenError`.
async fn open(root: &Path, name: &str) -> Result<(PathBuf, std::fs::Metadata), OpenError> {
    let cleaned = path_clean(&format!("/{name}"));
    let rel = cleaned.trim_start_matches('/');
    // filepath.Localize rejects NUL bytes.
    if rel.contains('\0') {
        return Err(OpenError::NotFound);
    }
    let full = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    let map = |err: std::io::Error| match err.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory => OpenError::NotFound,
        ErrorKind::PermissionDenied => OpenError::Forbidden,
        _ => OpenError::Other,
    };
    let file = tokio::fs::File::open(&full).await.map_err(map)?;
    let meta = file.metadata().await.map_err(map)?;
    Ok((full, meta))
}

/// `serveFile(w, r, fs, name, redirect=true)`
async fn serve_file(w: &mut GoWriter, req: &GoRequest<'_>, root: &Path, name: &str, url: &str) {
    if url.ends_with("/index.html") {
        w.local_redirect("./", req.raw_query);
        return;
    }
    let (full, meta) = match open(root, name).await {
        Ok(found) => found,
        Err(OpenError::NotFound) => {
            return w.serve_error("404 page not found", StatusCode::NOT_FOUND);
        }
        Err(OpenError::Forbidden) => {
            return w.serve_error("403 Forbidden", StatusCode::FORBIDDEN);
        }
        Err(OpenError::Other) => {
            return w.serve_error(
                "500 Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    if meta.is_dir() {
        if !url.ends_with('/') {
            w.local_redirect(&format!("{}/", path_base(url)), req.raw_query);
            return;
        }
        // Directory listings are unreachable: DisableIndex rejects every
        // path ending in "/" before the file server runs.
        return w.error("404 page not found", StatusCode::NOT_FOUND);
    }
    if url.ends_with('/') {
        let base = path_base(url);
        if base == "/" || base == "." {
            return w.serve_error(
                "http: attempting to traverse a non-directory",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
        w.local_redirect(&format!("../{base}"), req.raw_query);
        return;
    }
    let Ok(content) = tokio::fs::read(&full).await else {
        return w.serve_error(
            "500 Internal Server Error",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    };
    let modtime = meta.modified().ok();
    serve_content(w, req, &path_base(name), modtime, &content);
}

#[derive(PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

/// Seconds since the epoch, or `None` for Go's `isZeroTime`.
fn unix_secs(t: Option<SystemTime>) -> Option<i64> {
    let secs = i64::try_from(t?.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    (secs != 0).then_some(secs)
}

/// `http.ParseTime` (all three accepted formats), in seconds.
fn parse_http_secs(s: &str) -> Option<i64> {
    let t = httpdate::parse_http_date(s).ok()?;
    i64::try_from(t.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()
}

/// `scanETag`
fn scan_etag(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_matches([' ', '\t', '\n', '\r']);
    let start = if s.starts_with("W/") { 2 } else { 0 };
    let bytes = s.as_bytes();
    if s.len() < start + 2 || bytes[start] != b'"' {
        return None;
    }
    for (i, &c) in bytes.iter().enumerate().skip(start + 1) {
        match c {
            0x21 | 0x23..=0x7e | 0x80..=0xff => {}
            b'"' => return Some((&s[..=i], &s[i + 1..])),
            _ => return None,
        }
    }
    None
}

fn strong_match(a: &str, b: &str) -> bool {
    a == b && a.starts_with('"')
}

fn weak_match(a: &str, b: &str) -> bool {
    a.trim_start_matches("W/") == b.trim_start_matches("W/")
}

/// Shared loop of `checkIfMatch` / `checkIfNoneMatch`.
fn scan_list(
    value: &str,
    star: Cond,
    matches: impl Fn(&str) -> bool,
    found: Cond,
    end: Cond,
) -> Cond {
    let mut buf = value;
    loop {
        buf = buf.trim_matches([' ', '\t', '\n', '\r']);
        if buf.is_empty() {
            break;
        }
        if let Some(rest) = buf.strip_prefix(',') {
            buf = rest;
            continue;
        }
        if buf.starts_with('*') {
            return star;
        }
        let Some((etag, remain)) = scan_etag(buf) else {
            break;
        };
        if matches(etag) {
            return found;
        }
        buf = remain;
    }
    end
}

/// `checkPreconditions`; returns the effective `Range` header unless done.
fn check_preconditions(
    w: &mut GoWriter,
    req: &GoRequest<'_>,
    modtime: Option<i64>,
) -> Option<String> {
    let current_etag = w
        .headers
        .get(ETAG)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();

    let im = req.header(&IF_MATCH);
    let mut ch = if im.is_empty() {
        Cond::None
    } else {
        scan_list(
            &im,
            Cond::True,
            |e| strong_match(e, &current_etag),
            Cond::True,
            Cond::False,
        )
    };
    if ch == Cond::None {
        let ius = req.header(&IF_UNMODIFIED_SINCE);
        if let (false, Some(m), Some(t)) = (ius.is_empty(), modtime, parse_http_secs(&ius)) {
            ch = if m <= t { Cond::True } else { Cond::False };
        }
    }
    if ch == Cond::False {
        w.write_header(StatusCode::PRECONDITION_FAILED);
        return None;
    }

    let inm = req.header(&IF_NONE_MATCH);
    let none_match = if inm.is_empty() {
        Cond::None
    } else {
        scan_list(
            &inm,
            Cond::False,
            |e| weak_match(e, &current_etag),
            Cond::False,
            Cond::True,
        )
    };
    match none_match {
        Cond::False => {
            if req.is_get_or_head() {
                w.write_not_modified();
            } else {
                w.write_header(StatusCode::PRECONDITION_FAILED);
            }
            return None;
        }
        Cond::None => {
            let ims = req.header(&IF_MODIFIED_SINCE);
            if req.is_get_or_head()
                && let (false, Some(m), Some(t)) = (ims.is_empty(), modtime, parse_http_secs(&ims))
                && m <= t
            {
                w.write_not_modified();
                return None;
            }
        }
        Cond::True => {}
    }

    let range = req.header(&RANGE);
    if range.is_empty() {
        return Some(range);
    }
    // checkIfRange
    let ir = req.header(&IF_RANGE);
    if req.is_get_or_head() && !ir.is_empty() {
        let keep = if let Some((etag, _)) = scan_etag(&ir) {
            strong_match(etag, &current_etag)
        } else {
            match (modtime, parse_http_secs(&ir)) {
                (Some(m), Some(t)) => m == t,
                _ => false,
            }
        };
        if !keep {
            return Some(String::new());
        }
    }
    Some(range)
}

struct HttpRange {
    start: u64,
    length: u64,
}

impl HttpRange {
    fn content_range(&self, size: u64) -> String {
        format!(
            "bytes {}-{}/{size}",
            self.start,
            self.start + self.length - 1
        )
    }
}

enum RangeError {
    Invalid,
    NoOverlap,
}

/// `strconv.ParseInt(s, 10, 64)`
fn parse_i64(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `parseRange`
fn parse_range(s: &str, size: u64) -> Result<Vec<HttpRange>, RangeError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let Some(spec) = s.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let size_i = i64::try_from(size).map_err(|_| RangeError::Invalid)?;
    let trim = |x: &str| x.trim_matches([' ', '\t', '\n', '\r']).to_owned();
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for ra in spec.split(',') {
        let ra = trim(ra);
        if ra.is_empty() {
            continue;
        }
        let Some((start, end)) = ra.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (trim(start), trim(end));
        let (r_start, r_len) = if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let i = parse_i64(&end)
                .filter(|i| *i >= 0)
                .ok_or(RangeError::Invalid)?;
            let i = i.min(size_i);
            (size_i - i, i)
        } else {
            let i = parse_i64(&start)
                .filter(|i| *i >= 0)
                .ok_or(RangeError::Invalid)?;
            if i >= size_i {
                no_overlap = true;
                continue;
            }
            if end.is_empty() {
                (i, size_i - i)
            } else {
                let e = parse_i64(&end).ok_or(RangeError::Invalid)?;
                if i > e {
                    return Err(RangeError::Invalid);
                }
                (i, e.min(size_i - 1) - i + 1)
            }
        };
        ranges.push(HttpRange {
            start: u64::try_from(r_start).map_err(|_| RangeError::Invalid)?,
            length: u64::try_from(r_len).map_err(|_| RangeError::Invalid)?,
        });
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// `serveContent`
fn serve_content(
    w: &mut GoWriter,
    req: &GoRequest<'_>,
    name: &str,
    modtime: Option<SystemTime>,
    content: &[u8],
) {
    let mod_secs = unix_secs(modtime);
    // setLastModified
    if let (Some(t), Some(_)) = (modtime, mod_secs)
        && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(t))
    {
        w.headers.insert(LAST_MODIFIED, value);
    }
    let Some(range_header) = check_preconditions(w, req, mod_secs) else {
        return;
    };

    let ctype = if let Some(ct) = w.headers.get(CONTENT_TYPE) {
        String::from_utf8_lossy(ct.as_bytes()).into_owned()
    } else {
        let ct = type_by_extension(extension(name)).unwrap_or_else(|| detect_content_type(content));
        w.headers.insert(CONTENT_TYPE, HeaderValue::from_static(ct));
        ct.to_owned()
    };

    let size = u64::try_from(content.len()).unwrap_or(u64::MAX);
    let mut ranges = match parse_range(&range_header, size) {
        Ok(ranges) => ranges,
        Err(RangeError::NoOverlap) if size == 0 => Vec::new(),
        Err(RangeError::NoOverlap) => {
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}")) {
                w.headers.insert(CONTENT_RANGE, value);
            }
            return w.serve_error(
                "invalid range: failed to overlap",
                StatusCode::RANGE_NOT_SATISFIABLE,
            );
        }
        Err(RangeError::Invalid) => {
            return w.serve_error("invalid range", StatusCode::RANGE_NOT_SATISFIABLE);
        }
    };
    if ranges.iter().map(|r| r.length).sum::<u64>() > size {
        ranges.clear();
    }

    let slice = |r: &HttpRange| {
        let start = usize::try_from(r.start).unwrap_or(usize::MAX);
        let end = usize::try_from(r.start + r.length).unwrap_or(usize::MAX);
        content.get(start..end).unwrap_or_default()
    };
    let mut code = StatusCode::OK;
    let send: Vec<u8> = match ranges.len() {
        0 => content.to_vec(),
        1 => {
            code = StatusCode::PARTIAL_CONTENT;
            if let Ok(value) = HeaderValue::from_str(&ranges[0].content_range(size)) {
                w.headers.insert(CONTENT_RANGE, value);
            }
            slice(&ranges[0]).to_vec()
        }
        _ => {
            code = StatusCode::PARTIAL_CONTENT;
            // multipart.Writer with randomBoundary (30 random bytes, hex).
            let mut raw = [0_u8; 30];
            rand::fill(&mut raw);
            let boundary = hex::encode(raw);
            let mut body = Vec::new();
            for (i, r) in ranges.iter().enumerate() {
                let sep = if i == 0 { "" } else { "\r\n" };
                body.extend_from_slice(
                    format!(
                        "{sep}--{boundary}\r\nContent-Range: {}\r\nContent-Type: {ctype}\r\n\r\n",
                        r.content_range(size)
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(slice(r));
            }
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            if let Ok(value) =
                HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))
            {
                w.headers.insert(CONTENT_TYPE, value);
            }
            body
        }
    };

    w.headers
        .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if !ranges.is_empty() || req.encoding.is_none() {
        w.headers.insert(CONTENT_LENGTH, send.len().into());
    }
    w.write_header(code);
    if req.method != Method::HEAD {
        w.write(&send);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_go() {
        let ok = |s: &str, size: u64| -> Vec<(u64, u64)> {
            parse_range(s, size)
                .unwrap_or_else(|_| panic!("{s} should parse"))
                .iter()
                .map(|r| (r.start, r.length))
                .collect()
        };
        assert_eq!(ok("bytes=0-9", 100), vec![(0, 10)]);
        assert_eq!(ok("bytes=-5", 100), vec![(95, 5)]);
        assert_eq!(ok("bytes=90-", 100), vec![(90, 10)]);
        assert_eq!(ok("bytes=95-200", 100), vec![(95, 5)]);
        assert!(matches!(
            parse_range("bytes=100-", 100),
            Err(RangeError::NoOverlap)
        ));
        assert!(matches!(
            parse_range("bytes=5-1", 100),
            Err(RangeError::Invalid)
        ));
        assert!(matches!(
            parse_range("items=0-1", 100),
            Err(RangeError::Invalid)
        ));
    }

    #[test]
    fn fresh_matches_go_http_utils() {
        let mut req = HeaderMap::new();
        let mut res = HeaderMap::new();
        res.insert(ETAG, HeaderValue::from_static("5-abc"));
        assert!(!is_fresh(&req, &res));
        req.insert(IF_NONE_MATCH, HeaderValue::from_static("5-abc"));
        assert!(is_fresh(&req, &res));
        req.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("max-age=0, no-cache"),
        );
        assert!(!is_fresh(&req, &res));

        let mut req = HeaderMap::new();
        res.insert(
            LAST_MODIFIED,
            HeaderValue::from_static("Sat, 01 Jan 2000 00:00:00 GMT"),
        );
        req.insert(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sat, 01 Jan 2000 00:00:00 GMT"),
        );
        // Strictly before: equal timestamps are not fresh.
        assert!(!is_fresh(&req, &res));
    }

    #[test]
    fn path_base_matches_go() {
        assert_eq!(path_base("/a/b"), "b");
        assert_eq!(path_base("/a/b/"), "b");
        assert_eq!(path_base("/"), "/");
        assert_eq!(path_base(""), ".");
    }
}

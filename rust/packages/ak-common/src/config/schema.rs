use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub(super) const KEYS_TO_PARSE_AS_LIST: [&str; 5] = [
    "listen.http",
    "listen.https",
    "listen.metrics",
    "listen.trusted_proxy_cidrs",
    "log.http_headers",
];

/// Deserialize a list, ignoring empty entries.
///
/// The environment source splits values on `,`, so an empty variable
/// yields a single empty entry rather than an empty list.
fn deserialize_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr<Err: Display>,
{
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.parse().map_err(D::Error::custom))
        .collect()
}

/// authentik-rs: Go's `SplitHostPort` (2026.2.7 binds with `net.Listen("tcp", address)`).
fn split_go_host_port(address: &str) -> Result<(&str, &str), String> {
    let err = |why: &str| Err(format!("address {address}: {why}"));
    let Some(i) = address.rfind(':') else {
        return err("missing port in address");
    };
    let (host, j, k) = if address.starts_with('[') {
        let Some(end) = address.find(']') else {
            return err("missing ']' in address");
        };
        if end + 1 == address.len() {
            return err("missing port in address");
        }
        if end + 1 != i {
            if address.as_bytes()[end + 1] == b':' {
                return err("too many colons in address");
            }
            return err("missing port in address");
        }
        (&address[1..end], 1, end + 1)
    } else {
        let host = &address[..i];
        if host.contains(':') {
            return err("too many colons in address");
        }
        (host, 0, 0)
    };
    if address[j..].contains('[') {
        return err("unexpected '[' in address");
    }
    if address[k..].contains(']') {
        return err("unexpected ']' in address");
    }
    Ok((host, &address[i + 1..]))
}

/// authentik-rs: Go's `parsePort` followed by `LookupPort`'s range check. An
/// empty port is 0 (a random port), and a sign or leading zeros are accepted.
/// Go would look a non-numeric port up as a service name; that is rejected.
fn parse_go_port(port: &str) -> Result<u16, String> {
    let digits = port.strip_prefix(['+', '-']).unwrap_or(port);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("unsupported service name as port: {port}"));
    }
    let value = digits
        .bytes()
        .try_fold(0_u32, |n, d| {
            n.checked_mul(10)?.checked_add(u32::from(d - b'0'))
        })
        .unwrap_or(u32::MAX);
    match u16::try_from(value) {
        Ok(0) => Ok(0),
        Ok(n) if !port.starts_with('-') => Ok(n),
        _ => Err(format!("address {port}: invalid port")),
    }
}

/// authentik-rs: resolve a listen address like Go's `net.Listen("tcp", address)`.
///
/// An empty host is the wildcard, an IPv4-mapped IPv6 literal is IPv4, `::`
/// is turned into `0.0.0.0` (Go issue 18806), and a hostname resolves to its
/// first IPv4 address, else its first address. Wildcards are bound dual-stack
/// by `ak_axum::server`, as Go does.
pub fn parse_go_listen_addr(address: &str) -> Result<SocketAddr, String> {
    let (host, port) = split_go_host_port(address)?;
    let port = parse_go_port(port)?;
    let addrs: Vec<SocketAddr> = if host.is_empty() {
        vec![(Ipv4Addr::UNSPECIFIED, port).into()]
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        vec![(ip, port).into()]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|err| format!("lookup {host}: {err}"))?
            .collect()
    };
    let addrs: Vec<SocketAddr> = match addrs.as_slice() {
        [addr] if addr.ip() == Ipv6Addr::UNSPECIFIED => vec![(Ipv4Addr::UNSPECIFIED, port).into()],
        _ => addrs
            .into_iter()
            .map(|addr| match addr.ip().to_canonical() {
                ip @ IpAddr::V4(_) => (ip, port).into(),
                IpAddr::V6(_) => addr,
            })
            .collect(),
    };
    addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| format!("lookup {host}: no such host"))
}

/// authentik-rs: 2026.2.7 configures each listener as one address string
/// (`http: 0.0.0.0:9000`), upstream Rust as a list. Accept both, ignoring
/// empty entries like [`deserialize_list`], and resolve each entry the way Go
/// does.
fn deserialize_listen<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    let entries = match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(entry) => vec![entry],
        OneOrMany::Many(entries) => entries,
    };
    entries
        .iter()
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_go_listen_addr(entry).map_err(D::Error::custom))
        .collect()
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    // The value comes as a number from config files but as a string from env vars.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }

    match Option::<NumOrStr>::deserialize(deserializer)? {
        None => Ok(None),
        Some(NumOrStr::Num(n)) => Ok(Some(n)),
        Some(NumOrStr::Str(s)) => {
            let s = s.trim();
            if s.is_empty() || s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("null") {
                Ok(None)
            } else {
                s.parse().map(Some).map_err(D::Error::custom)
            }
        }
    }
}

mod sealed {
    use std::{fmt::Display, str::FromStr};

    /// Numeric config types that may be provided either as a native number (YAML / environment
    /// variables) or as a string (from `file://` / `env://` references, which resolve to strings).
    ///
    /// Sealed so [`super::deserialize_str_or_num`] can only be attached to numeric fields:
    /// applying it to a `String` field would silently coerce values that must stay strings (e.g. an
    /// all-digit password read from a file), which is a compile error instead.
    pub(super) trait Numeric: FromStr<Err: Display> {}

    impl Numeric for u16 {}
    impl Numeric for u64 {}
    impl Numeric for f32 {}
    impl Numeric for std::num::NonZeroUsize {}
}

/// Deserialize a numeric field that may arrive as a number or as a string.
///
/// YAML numbers and environment variables (coerced by `config_rs`) arrive already typed; `file://`
/// and `env://` references resolve to strings and are parsed here. Because this is opt-in per
/// field, string-typed fields keep their raw value and are never coerced.
fn deserialize_str_or_num<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + sealed::Numeric,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr<T> {
        Num(T),
        Str(String),
    }

    match NumOrStr::<T>::deserialize(deserializer)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Str(s) => s.trim().parse().map_err(D::Error::custom),
    }
}

/// Deserialize a boolean that may arrive as a native bool or as a string (`"true"`/`"false"`,
/// case-insensitive), for the same `file://` / `env://` reason as [`deserialize_str_or_num`].
fn deserialize_str_or_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrStr {
        Bool(bool),
        Str(String),
    }

    match BoolOrStr::deserialize(deserializer)? {
        BoolOrStr::Bool(b) => Ok(b),
        BoolOrStr::Str(s) => s
            .trim()
            .to_ascii_lowercase()
            .parse()
            .map_err(D::Error::custom),
    }
}

/// Like [`deserialize_str_or_bool`] but for optional booleans.
fn deserialize_optional_str_or_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrStr {
        Bool(bool),
        Str(String),
    }

    Ok(match Option::<BoolOrStr>::deserialize(deserializer)? {
        None => None,
        Some(BoolOrStr::Bool(b)) => Some(b),
        Some(BoolOrStr::Str(s)) => Some(
            s.trim()
                .to_ascii_lowercase()
                .parse()
                .map_err(D::Error::custom)?,
        ),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub postgresql: PostgreSQLConfig,

    pub listen: ListenConfig,

    #[serde(deserialize_with = "deserialize_str_or_bool")]
    pub debug: bool,
    #[serde(default)]
    pub secret_key: String,

    pub log_level: String,
    pub log: LogConfig,

    pub error_reporting: ErrorReportingConfig,

    pub compliance: ComplianceConfig,

    pub web: WebConfig,

    pub worker: WorkerConfig,

    pub storage: StorageConfig,

    pub outposts: OutpostConfig,

    // authentik-rs: read by the ported API (session middleware, avatars'
    // GeoIP context).
    #[serde(default)]
    pub events: EventsConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub cookie_domain: Option<String>,

    // Outpost specific fields
    pub host: Option<String>,
    pub host_browser: Option<String>,
    pub token: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_str_or_bool")]
    pub insecure: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgreSQLConfig {
    pub host: String,
    #[serde(deserialize_with = "deserialize_str_or_num")]
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,

    pub sslmode: String,
    pub sslrootcert: Option<String>,
    pub sslcert: Option<String>,
    pub sslkey: Option<String>,

    #[serde(deserialize_with = "deserialize_optional_u64")]
    pub conn_max_age: Option<u64>,
    #[serde(deserialize_with = "deserialize_str_or_bool")]
    pub conn_health_checks: bool,

    pub default_schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    // authentik-rs: `deserialize_listen` (2026.2.7 scalar addresses).
    #[serde(deserialize_with = "deserialize_listen")]
    pub http: Vec<SocketAddr>,
    #[serde(deserialize_with = "deserialize_listen")]
    pub https: Vec<SocketAddr>,
    #[serde(deserialize_with = "deserialize_listen")]
    pub metrics: Vec<SocketAddr>,
    pub debug_tokio: Option<SocketAddr>,
    #[serde(deserialize_with = "deserialize_list")]
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(deserialize_with = "deserialize_list")]
    pub http_headers: Vec<String>,
    pub rust_log: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReportingConfig {
    #[serde(deserialize_with = "deserialize_str_or_bool")]
    pub enabled: bool,
    pub sentry_dsn: Option<String>,
    pub environment: String,
    #[serde(deserialize_with = "deserialize_str_or_bool")]
    pub send_pii: bool,
    #[serde(deserialize_with = "deserialize_str_or_num")]
    pub sample_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub fips: ComplianceFipsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFipsConfig {
    #[serde(deserialize_with = "deserialize_str_or_bool")]
    pub enabled: bool,
}

/// `events.context_processors`: the `MaxMind` database paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventsConfig {
    #[serde(default)]
    pub context_processors: ContextProcessorsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextProcessorsConfig {
    #[serde(default)]
    pub geoip: Option<String>,
    #[serde(default)]
    pub asn: Option<String>,
}

/// `sessions`: `unauthenticated_age` is `SESSION_COOKIE_AGE` as a
/// `timedelta_from_string` expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionsConfig {
    pub unauthenticated_age: String,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            unauthenticated_age: "days=1".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub path: String,
    pub timeout_http_read_header: String,
    pub timeout_http_read: String,
    pub timeout_http_write: String,
    pub timeout_http_idle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    #[serde(deserialize_with = "deserialize_str_or_num")]
    pub processes: NonZeroUsize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: String,
    pub file: StorageFileConfig,
    pub media: Option<StorageOverrideConfig>,
    pub reports: Option<StorageOverrideConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFileConfig {
    pub path: PathBuf,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageOverrideConfig {
    pub backend: Option<String>,
    pub file: Option<StorageFileOverrideConfig>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageFileOverrideConfig {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutpostConfig {
    pub disable_embedded_outpost: bool,
}

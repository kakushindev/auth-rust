//! `MaxMind` DB lookups as 2026.2.7 makes them: `maxminddb` 3.0 (the reader),
//! `geoip2` 5.2 (`Reader.asn` / `Reader.city` and its record models) and
//! authentik's `MMDBContextProcessor` (load once, reload when the file's
//! modification time grows, unconfigured when the file cannot be opened).
//!
//! Only what authentik reads is modelled: the ASN number and network, and the
//! continent, country and city records, compared as `geoip2` compares them
//! (`isinstance` and `to_dict()` equality).

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::SystemTime,
};

/// `b"\xab\xcd\xefMaxMind.com"`, searched from the end of the file.
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// `_DATA_SECTION_SEPARATOR_SIZE`.
const DATA_SECTION_SEPARATOR_SIZE: usize = 16;
/// Deeper data than this is corrupt (Python would hit its recursion limit).
const MAX_DATA_DEPTH: usize = 512;

/// A decoded data-section value, as `maxminddb` returns it.
#[derive(Debug, Clone)]
pub enum Value {
    Str(String),
    Double(f64),
    Bytes(Vec<u8>),
    /// uint16, uint32, uint64 and uint128.
    Uint(u128),
    Int(i32),
    /// A `dict`: duplicate keys keep the last value, as in Python.
    Map(Vec<(String, Self)>),
    Array(Vec<Self>),
    Bool(bool),
    /// A float32, widened as `struct.unpack("!f")` does.
    Float(f64),
}

impl Value {
    /// `dict.get(key)`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(items) => items.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value as a Python number, for cross-type `==` (`True == 1 == 1.0`).
    fn number(&self) -> Option<f64> {
        #[expect(
            clippy::as_conversions,
            clippy::cast_precision_loss,
            reason = "only compared for equality, as Python compares int and float"
        )]
        match self {
            Self::Uint(n) => Some(*n as f64),
            Self::Int(n) => Some(f64::from(*n)),
            Self::Double(f) | Self::Float(f) => Some(*f),
            Self::Bool(b) => Some(f64::from(u8::from(*b))),
            _ => None,
        }
    }

    /// Python `==`.
    #[must_use]
    pub fn py_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.py_eq(y))
            }
            (Self::Map(_), Self::Map(_)) => dict_eq(self, other),
            // Exact integers compare exactly; anything with a float compares
            // as Python compares int and float (exactly, but f64 is enough
            // for MaxMind data).
            (Self::Uint(a), Self::Uint(b)) => a == b,
            _ => match (self.number(), other.number()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }
}

/// Unique keys, the last value winning, as a Python `dict` holds them.
fn dict_entries(value: &Value) -> Vec<(&str, &Value)> {
    let Value::Map(items) = value else {
        return Vec::new();
    };
    let mut out: Vec<(&str, &Value)> = Vec::new();
    for (k, v) in items {
        if let Some(slot) = out.iter_mut().find(|(key, _)| *key == k.as_str()) {
            slot.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
}

fn dict_eq(a: &Value, b: &Value) -> bool {
    let (a, b) = (dict_entries(a), dict_entries(b));
    a.len() == b.len()
        && a.iter()
            .all(|(k, v)| b.iter().any(|(k2, v2)| k == k2 && v.py_eq(v2)))
}

/// Why a database cannot be used.
#[derive(Debug)]
pub enum OpenError {
    /// `OSError`: authentik logs it and leaves the processor unconfigured.
    Io(std::io::Error),
    /// `InvalidDatabaseError`: it escapes (authentik fails to start).
    Invalid(&'static str),
}

/// Why a lookup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// `ValueError` (an IPv6 address in an IPv4 database, invalid UTF-8):
    /// authentik's wrappers answer `None`.
    Value,
    /// `TypeError` (`geoip2` used with the wrong database type, a record
    /// that cannot be passed as keyword arguments): escapes as a 500.
    Type,
    /// `InvalidDatabaseError`: escapes as a 500.
    Invalid(&'static str),
}

/// An open `MaxMind` DB.
#[derive(Debug)]
pub struct Reader {
    buf: Vec<u8>,
    node_count: usize,
    record_size: usize,
    ip_version: u128,
    search_tree_size: usize,
    ipv4_start: usize,
    database_type: String,
}

struct Decoder<'a> {
    buf: &'a [u8],
    pointer_base: usize,
}

impl Decoder<'_> {
    fn byte(&self, offset: usize) -> Result<usize, LookupError> {
        self.buf
            .get(offset)
            .map(|&b| usize::from(b))
            .ok_or(LookupError::Invalid("unexpected end of data"))
    }

    fn slice(&self, offset: usize, len: usize) -> Result<&[u8], LookupError> {
        offset
            .checked_add(len)
            .and_then(|end| self.buf.get(offset..end))
            .ok_or(LookupError::Invalid("unexpected end of data"))
    }

    fn be(&self, offset: usize, len: usize) -> Result<usize, LookupError> {
        Ok(self
            .slice(offset, len)?
            .iter()
            .fold(0_usize, |acc, &b| (acc << 8_u32) | usize::from(b)))
    }

    fn decode(&self, offset: usize, depth: usize) -> Result<(Value, usize), LookupError> {
        if depth > MAX_DATA_DEPTH {
            return Err(LookupError::Invalid("data nested too deeply"));
        }
        let ctrl = self.byte(offset)?;
        let mut offset = offset + 1;
        let mut type_num = ctrl >> 5_u32;
        if type_num == 0 {
            type_num = self.byte(offset)? + 7;
            offset += 1;
        }
        let mut size = ctrl & 0x1f;
        if type_num == 1 {
            // `_decode_pointer`: the size bits hold the pointer's length.
            let pointer_size = (size >> 3_u32) + 1;
            let low = size & 0x7;
            let pointer = match pointer_size {
                1 => (low << 8_u32 | self.be(offset, 1)?) + self.pointer_base,
                2 => (low << 16_u32 | self.be(offset, 2)?) + 2048 + self.pointer_base,
                3 => (low << 24_u32 | self.be(offset, 3)?) + 526_336 + self.pointer_base,
                _ => self.be(offset, 4)? + self.pointer_base,
            };
            let (value, _) = self.decode(pointer, depth + 1)?;
            return Ok((value, offset + pointer_size));
        }
        match size {
            29 => {
                size = 29 + self.byte(offset)?;
                offset += 1;
            }
            30 => {
                size = 285 + self.be(offset, 2)?;
                offset += 2;
            }
            31 => {
                size = 65_821 + self.be(offset, 3)?;
                offset += 3;
            }
            _ => {}
        }
        let end = offset
            .checked_add(size)
            .ok_or(LookupError::Invalid("size overflows"))?;
        Ok(match type_num {
            2 => (
                Value::Str(
                    String::from_utf8(self.slice(offset, size)?.to_vec())
                        .map_err(|_| LookupError::Value)?,
                ),
                end,
            ),
            3 => {
                let bytes: [u8; 8] = self
                    .slice(offset, size)?
                    .try_into()
                    .map_err(|_| LookupError::Invalid("bad double size"))?;
                (Value::Double(f64::from_be_bytes(bytes)), end)
            }
            4 => (Value::Bytes(self.slice(offset, size)?.to_vec()), end),
            5 | 6 | 9 | 10 => {
                let n = self
                    .slice(offset, size)?
                    .iter()
                    .try_fold(0_u128, |acc, &b| {
                        acc.checked_mul(256).map(|v| v | u128::from(b))
                    })
                    .ok_or(LookupError::Invalid("uint too large"))?;
                (Value::Uint(n), end)
            }
            7 => {
                let mut items = Vec::new();
                let mut at = offset;
                for _ in 0..size {
                    let (key, next) = self.decode(at, depth + 1)?;
                    let (value, next) = self.decode(next, depth + 1)?;
                    at = next;
                    // `geoip2` passes records as keyword arguments, which
                    // must be strings.
                    let Value::Str(key) = key else {
                        return Err(LookupError::Type);
                    };
                    items.push((key, value));
                }
                (Value::Map(items), at)
            }
            8 => {
                if size > 4 {
                    return Err(LookupError::Invalid("bad int32 size"));
                }
                let raw = self.be(offset, size)?;
                let n = u32::try_from(raw).map_err(|_| LookupError::Invalid("bad int32"))?;
                (Value::Int(i32::from_be_bytes(n.to_be_bytes())), end)
            }
            11 => {
                let mut items = Vec::new();
                let mut at = offset;
                for _ in 0..size {
                    let (value, next) = self.decode(at, depth + 1)?;
                    at = next;
                    items.push(value);
                }
                (Value::Array(items), at)
            }
            14 => (Value::Bool(size != 0), offset),
            15 => {
                let bytes: [u8; 4] = self
                    .slice(offset, size)?
                    .try_into()
                    .map_err(|_| LookupError::Invalid("bad float size"))?;
                (Value::Float(f64::from(f32::from_be_bytes(bytes))), end)
            }
            _ => return Err(LookupError::Invalid("unexpected type number")),
        })
    }
}

impl Reader {
    /// `maxminddb.open_database(path)`.
    ///
    /// # Errors
    ///
    /// [`OpenError::Io`] when the file cannot be read, [`OpenError::Invalid`]
    /// when it is not a `MaxMind` DB.
    pub fn open(path: &Path) -> Result<Self, OpenError> {
        Self::from_bytes(std::fs::read(path).map_err(OpenError::Io)?)
    }

    /// A `MaxMind` DB already in memory.
    ///
    /// # Errors
    ///
    /// [`OpenError::Invalid`] when it is not a `MaxMind` DB.
    pub fn from_bytes(buf: Vec<u8>) -> Result<Self, OpenError> {
        let invalid = OpenError::Invalid;
        let search_from = buf.len().saturating_sub(128 * 1024);
        let start = buf
            .get(search_from..)
            .and_then(|tail| {
                tail.windows(METADATA_MARKER.len())
                    .rposition(|w| w == METADATA_MARKER)
            })
            .map(|at| search_from + at + METADATA_MARKER.len())
            .ok_or_else(|| {
                invalid("Error opening database file. Is this a valid MaxMind DB file?")
            })?;
        let decoder = Decoder {
            buf: &buf,
            pointer_base: start,
        };
        let (metadata, _) = decoder
            .decode(start, 0)
            .map_err(|_| invalid("invalid metadata"))?;
        let uint = |key: &str| match metadata.get(key) {
            Some(Value::Uint(n)) => Ok(*n),
            _ => Err(invalid("invalid metadata")),
        };
        let to_usize = |n: u128| usize::try_from(n).map_err(|_| invalid("invalid metadata"));
        let node_count = to_usize(uint("node_count")?)?;
        let record_size = to_usize(uint("record_size")?)?;
        let ip_version = uint("ip_version")?;
        if !matches!(record_size, 24 | 28 | 32) {
            return Err(invalid("Unknown record size"));
        }
        let database_type = match metadata.get("database_type") {
            Some(Value::Str(s)) => s.clone(),
            _ => return Err(invalid("invalid metadata")),
        };
        let search_tree_size = node_count
            .checked_mul(record_size / 4)
            .ok_or_else(|| invalid("invalid metadata"))?;
        let mut reader = Self {
            buf,
            node_count,
            record_size,
            ip_version,
            search_tree_size,
            ipv4_start: 0,
            database_type,
        };
        if reader.ip_version == 6 {
            let mut node = 0;
            for _ in 0..96_u32 {
                if node >= reader.node_count {
                    break;
                }
                node = reader
                    .read_node(node, 0)
                    .map_err(|_| invalid("The MaxMind DB file's search tree is corrupt"))?;
            }
            reader.ipv4_start = node;
        }
        Ok(reader)
    }

    /// The metadata's `database_type`.
    #[must_use]
    pub fn database_type(&self) -> &str {
        &self.database_type
    }

    fn read_node(&self, node: usize, index: usize) -> Result<usize, LookupError> {
        let base = node * (self.record_size / 4);
        let d = Decoder {
            buf: &self.buf,
            pointer_base: 0,
        };
        match self.record_size {
            24 => d.be(base + index * 3, 3),
            28 => {
                let middle = d.byte(base + 3)?;
                if index == 0 {
                    Ok(((middle & 0xf0) << 20) | d.be(base, 3)?)
                } else {
                    Ok(((middle & 0x0f) << 24) | d.be(base + 4, 3)?)
                }
            }
            _ => d.be(base + index * 4, 4),
        }
    }

    /// `Reader.get_with_prefix_len(ip)`: the record and the prefix length.
    ///
    /// # Errors
    ///
    /// [`LookupError`] as `maxminddb` raises.
    pub fn get_with_prefix_len(&self, ip: IpAddr) -> Result<(Option<Value>, u32), LookupError> {
        let packed: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    return Err(LookupError::Value);
                }
                v6.octets().to_vec()
            }
        };
        let bit_count = packed.len() * 8;
        let mut node = if self.ip_version == 6 && bit_count == 32 {
            self.ipv4_start
        } else {
            0
        };
        let mut i = 0;
        while i < bit_count && node < self.node_count {
            let bit = usize::from(1_u8 & (packed[i >> 3_u32] >> (7 - (i % 8))));
            node = self.read_node(node, bit)?;
            i += 1;
        }
        let prefix_len = u32::try_from(i).unwrap_or(u32::MAX);
        if node == self.node_count {
            return Ok((None, prefix_len));
        }
        if node < self.node_count {
            return Err(LookupError::Invalid("Invalid node in search tree"));
        }
        let resolved = node - self.node_count + self.search_tree_size;
        if resolved >= self.buf.len() {
            return Err(LookupError::Invalid(
                "The MaxMind DB file's search tree is corrupt",
            ));
        }
        let decoder = Decoder {
            buf: &self.buf,
            pointer_base: self.search_tree_size + DATA_SECTION_SEPARATOR_SIZE,
        };
        let (value, _) = decoder.decode(resolved, 0)?;
        Ok((Some(value), prefix_len))
    }
}

/// An IP network as `ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub address: IpAddr,
    pub prefix_len: u32,
}

impl Network {
    fn new(ip: IpAddr, prefix_len: u32) -> Self {
        let address = match ip {
            IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl(32 - prefix_len.min(32)).unwrap_or(0);
                IpAddr::V4((u32::from(v4) & mask).into())
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - prefix_len.min(128))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(v6) & mask).into())
            }
        };
        Self {
            address,
            prefix_len,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// `geoip2.models.ASN`: what authentik reads of it.
#[derive(Debug, Clone)]
pub struct Asn {
    pub autonomous_system_number: Option<Value>,
    pub autonomous_system_organization: Option<Value>,
    pub network: Network,
}

/// A `geoip2` place record (`Continent`, `Country`, `City`) as its
/// `to_dict()`: the fields it keeps, with `None`, `False`, `{}` and `[]`
/// dropped.
#[derive(Debug, Clone)]
pub struct Record(Vec<(&'static str, Value)>);

impl Record {
    fn new(source: Option<&Value>, fields: &[&'static str]) -> Result<Self, LookupError> {
        // `Record(**(source or {}))`: a non-dict cannot be keyword arguments.
        let source = match source {
            Some(map @ Value::Map(_)) => Some(map),
            None | Some(Value::Bool(false)) => None,
            Some(Value::Array(a)) if a.is_empty() => None,
            Some(Value::Str(s)) if s.is_empty() => None,
            Some(Value::Bytes(b)) if b.is_empty() => None,
            Some(_) => return Err(LookupError::Type),
        };
        let mut out = Vec::new();
        for field in fields {
            let Some(value) = source.and_then(|s| s.get(field)) else {
                continue;
            };
            let kept = match value {
                Value::Bool(false) => None,
                Value::Map(m) if m.is_empty() => None,
                Value::Array(a) if a.is_empty() => None,
                v => Some(v.clone()),
            };
            if let Some(v) = kept {
                out.push((*field, v));
            }
        }
        Ok(Self(out))
    }

    /// The fields `to_dict()` keeps, in the record's order.
    #[must_use]
    pub fn fields(&self) -> &[(&'static str, Value)] {
        &self.0
    }

    /// A field's value, if `to_dict()` keeps it.
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == field).map(|(_, v)| v)
    }

    /// `to_dict() == other.to_dict()`.
    #[must_use]
    pub fn py_eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .all(|(k, v)| other.get(k).is_some_and(|o| v.py_eq(o)))
    }
}

/// `geoip2.models.City`: what authentik reads of it.
#[derive(Debug, Clone)]
pub struct City {
    pub continent: Record,
    pub country: Record,
    pub city: Record,
    /// `location.latitude` / `location.longitude`.
    pub latitude: Option<Value>,
    pub longitude: Option<Value>,
    /// `city.name` with the default locales (`["en"]`).
    pub city_name: Option<Value>,
}

/// `geoip2.database.Reader`.
impl Reader {
    fn model_record(&self, kind: &str, ip: IpAddr) -> Result<Option<(Value, u32)>, LookupError> {
        if !self.database_type.contains(kind) {
            return Err(LookupError::Type);
        }
        match self.get_with_prefix_len(ip)? {
            // `AddressNotFoundError`.
            (None, _) => Ok(None),
            (Some(record @ Value::Map(_)), prefix_len) => Ok(Some((record, prefix_len))),
            (Some(_), _) => Err(LookupError::Invalid("Expected record to be a dict")),
        }
    }

    /// `Reader.asn(ip)`, `None` for `AddressNotFoundError`.
    ///
    /// # Errors
    ///
    /// [`LookupError`] as `geoip2` raises.
    pub fn asn(&self, ip: IpAddr) -> Result<Option<Asn>, LookupError> {
        Ok(self
            .model_record("GeoLite2-ASN", ip)?
            .map(|(record, prefix_len)| Asn {
                autonomous_system_number: record.get("autonomous_system_number").cloned(),
                autonomous_system_organization: record
                    .get("autonomous_system_organization")
                    .cloned(),
                network: Network::new(ip, prefix_len),
            }))
    }

    /// `Reader.city(ip)`, `None` for `AddressNotFoundError`.
    ///
    /// # Errors
    ///
    /// [`LookupError`] as `geoip2` raises.
    pub fn city(&self, ip: IpAddr) -> Result<Option<City>, LookupError> {
        let Some((record, _)) = self.model_record("City", ip)? else {
            return Ok(None);
        };
        Ok(Some(City {
            continent: Record::new(record.get("continent"), &["code", "geoname_id", "names"])?,
            country: Record::new(
                record.get("country"),
                &[
                    "confidence",
                    "geoname_id",
                    "is_in_european_union",
                    "iso_code",
                    "names",
                ],
            )?,
            city: Record::new(record.get("city"), &["confidence", "geoname_id", "names"])?,
            latitude: Record::new(record.get("location"), &["latitude"])?
                .get("latitude")
                .cloned(),
            longitude: Record::new(record.get("location"), &["longitude"])?
                .get("longitude")
                .cloned(),
            city_name: record
                .get("city")
                .and_then(|c| c.get("names"))
                .and_then(|n| n.get("en"))
                .cloned(),
        }))
    }
}

/// `ipaddress.ip_address(s)` for the strings authentik passes: Python accepts
/// an IPv6 scope (`fe80::1%eth0`), which the lookup ignores.
#[must_use]
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    let (addr, scope) = s.split_once('%')?;
    if scope.is_empty() || scope.contains('/') {
        return None;
    }
    addr.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

/// `MMDBContextProcessor`: a database path, loaded at start and reloaded
/// whenever the file's modification time grows.
#[derive(Debug)]
pub struct Processor {
    path: Option<PathBuf>,
    state: Mutex<(Option<Arc<Reader>>, Option<SystemTime>)>,
}

impl Processor {
    /// `__init__` + `load()`; an empty path is unconfigured.
    ///
    /// # Errors
    ///
    /// [`OpenError::Invalid`] escapes as it does from Python's import of the
    /// context processors; an unreadable file only leaves it unconfigured.
    pub fn new(path: Option<&str>) -> Result<Self, OpenError> {
        let path = path.filter(|p| !p.is_empty()).map(PathBuf::from);
        let processor = Self {
            path,
            state: Mutex::new((None, None)),
        };
        processor.load()?;
        Ok(processor)
    }

    fn load(&self) -> Result<(), OpenError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        match Reader::open(path) {
            Ok(reader) => {
                let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
                *self.state.lock().unwrap_or_else(PoisonError::into_inner) =
                    (Some(Arc::new(reader)), mtime);
                Ok(())
            }
            Err(OpenError::Io(_)) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// The current reader, after `check_expired()`; `None` when unconfigured.
    ///
    /// # Errors
    ///
    /// A reload that finds an invalid database.
    pub fn reader(&self) -> Result<Option<Arc<Reader>>, OpenError> {
        let (reader, last) = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if reader.is_none() {
            // `configured()` is checked before `check_expired()`.
            return Ok(None);
        }
        if let Some(path) = &self.path
            && let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified())
            && last.is_none_or(|last| last < mtime)
        {
            self.load()?;
            return Ok(self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .0
                .clone());
        }
        Ok(reader)
    }
}

//! `BoundSessionMiddleware.recheck_session`: a session bound to its network
//! (ASN, network, IP) or location (continent, country, city) at login
//! breaks when a request from another IP leaves the binding.

use ak_geoip::{Asn, City, LookupError, OpenError, Processor, Record, parse_ip};

/// `SESSION_KEY_BINDING_NET`.
pub const SESSION_KEY_BINDING_NET: &str = "authentik/stages/user_login/binding/net";
/// `SESSION_KEY_BINDING_GEO`.
pub const SESSION_KEY_BINDING_GEO: &str = "authentik/stages/user_login/binding/geo";
/// `NetworkBinding.NO_BINDING` / `GeoIPBinding.NO_BINDING`.
const NO_BINDING: &str = "no_binding";

/// authentik's ASN and `GeoIP` context processors.
#[derive(Debug)]
pub struct GeoIp {
    pub asn: Processor,
    pub city: Processor,
}

impl GeoIp {
    /// `ASN_CONTEXT_PROCESSOR` and `GEOIP_CONTEXT_PROCESSOR` for the
    /// `events.context_processors.asn` / `.geoip` paths.
    ///
    /// # Errors
    ///
    /// An invalid database, which stops authentik from starting.
    pub fn new(asn_path: Option<&str>, city_path: Option<&str>) -> Result<Self, OpenError> {
        Ok(Self {
            asn: Processor::new(asn_path)?,
            city: Processor::new(city_path)?,
        })
    }

    /// Neither database configured.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            asn: Processor::new(None).unwrap_or_else(|_| unreachable!("no path")),
            city: Processor::new(None).unwrap_or_else(|_| unreachable!("no path")),
        }
    }

    /// `ASN_CONTEXT_PROCESSOR.asn(ip)`: `None` when unconfigured, for
    /// `GeoIP2Error` and `ValueError`.
    fn asn(&self, ip: &str) -> Result<Option<Asn>, Error> {
        let Some(reader) = self.asn.reader().map_err(|_| Error::InvalidDatabase)? else {
            return Ok(None);
        };
        let Some(ip) = parse_ip(ip) else {
            return Ok(None);
        };
        match reader.asn(ip) {
            Ok(asn) => Ok(asn),
            Err(LookupError::Value) => Ok(None),
            Err(LookupError::Type) => Err(Error::Type),
            Err(LookupError::Invalid(_)) => Err(Error::InvalidDatabase),
        }
    }

    /// `GEOIP_CONTEXT_PROCESSOR.city(ip)`.
    fn city(&self, ip: &str) -> Result<Option<City>, Error> {
        let Some(reader) = self.city.reader().map_err(|_| Error::InvalidDatabase)? else {
            return Ok(None);
        };
        let Some(ip) = parse_ip(ip) else {
            return Ok(None);
        };
        match reader.city(ip) {
            Ok(city) => Ok(city),
            Err(LookupError::Value) => Ok(None),
            Err(LookupError::Type) => Err(Error::Type),
            Err(LookupError::Invalid(_)) => Err(Error::InvalidDatabase),
        }
    }
}

/// An exception escaping the middleware (a 500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `TypeError`: a database of the wrong type.
    Type,
    /// `InvalidDatabaseError`.
    InvalidDatabase,
}

/// The result of `recheck_session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// Same IP, or nothing bound: the session is left alone.
    Unchanged,
    /// The new IP is within the binding; with a binding key in the session,
    /// `session["last_ip"]` becomes the new IP (the session is modified).
    Passed { set_last_ip: bool },
    /// `SessionBindingBroken(reason, …)`: logout and a redirect to login.
    Broken(&'static str),
}

/// A binding as the session holds it: `None` when absent (`NO_BINDING`).
/// `Some(None)` is a value that is not a string (it is not `NO_BINDING`
/// either, and matches no mode).
pub type Binding = Option<Option<String>>;

fn is_bound(binding: &Binding) -> bool {
    match binding {
        None => false,
        Some(value) => value.as_deref() != Some(NO_BINDING),
    }
}

fn mode(binding: &Binding) -> &str {
    binding
        .as_ref()
        .and_then(Option::as_deref)
        .unwrap_or_default()
}

fn recheck_net(
    geoip: &GeoIp,
    binding: &str,
    last_ip: &str,
    new_ip: &str,
) -> Result<Option<&'static str>, Error> {
    let (Some(last), Some(new)) = (geoip.asn(last_ip)?, geoip.asn(new_ip)?) else {
        return Ok(Some("network.missing"));
    };
    if matches!(
        binding,
        "bind_asn" | "bind_asn_network" | "bind_asn_network_ip"
    ) {
        let same = match (
            &last.autonomous_system_number,
            &new.autonomous_system_number,
        ) {
            (Some(a), Some(b)) => a.py_eq(b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            return Ok(Some("network.asn"));
        }
    }
    if matches!(binding, "bind_asn_network" | "bind_asn_network_ip") && last.network != new.network
    {
        return Ok(Some("network.asn_network"));
    }
    if binding == "bind_asn_network_ip" && last_ip != new_ip {
        return Ok(Some("network.ip"));
    }
    Ok(None)
}

fn recheck_geo(
    geoip: &GeoIp,
    binding: &str,
    last_ip: &str,
    new_ip: &str,
) -> Result<Option<&'static str>, Error> {
    let (Some(last), Some(new)) = (geoip.city(last_ip)?, geoip.city(new_ip)?) else {
        return Ok(Some("geoip.missing"));
    };
    let differs = |a: &Record, b: &Record| !a.py_eq(b);
    if matches!(
        binding,
        "bind_continent" | "bind_continent_country" | "bind_continent_country_city"
    ) && differs(&last.continent, &new.continent)
    {
        return Ok(Some("geoip.continent"));
    }
    if matches!(
        binding,
        "bind_continent_country" | "bind_continent_country_city"
    ) && differs(&last.country, &new.country)
    {
        return Ok(Some("geoip.country"));
    }
    if binding == "bind_continent_country_city" && differs(&last.city, &new.city) {
        return Ok(Some("geoip.city"));
    }
    Ok(None)
}

/// `recheck_session(request)`: `last_ip` is `session["last_ip"]` (`None`
/// without a session), `new_ip` the client IP.
///
/// # Errors
///
/// [`Error`] where Python raises past the middleware.
pub fn recheck(
    geoip: &GeoIp,
    net: &Binding,
    geo: &Binding,
    last_ip: Option<&str>,
    new_ip: &str,
) -> Result<Recheck, Error> {
    if last_ip == Some(new_ip) {
        return Ok(Recheck::Unchanged);
    }
    // A session with a binding always has a `last_ip` (the column is
    // `NOT NULL`); without one there is nothing to compare against.
    let last = last_ip.unwrap_or_default();
    if is_bound(net)
        && let Some(reason) = recheck_net(geoip, mode(net), last, new_ip)?
    {
        return Ok(Recheck::Broken(reason));
    }
    if is_bound(geo)
        && let Some(reason) = recheck_geo(geoip, mode(geo), last, new_ip)?
    {
        return Ok(Recheck::Broken(reason));
    }
    Ok(Recheck::Passed {
        set_last_ip: net.is_some() || geo.is_some(),
    })
}

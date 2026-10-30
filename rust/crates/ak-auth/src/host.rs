//! `HttpRequest.get_host()` with authentik's `ALLOWED_HOSTS = ["*"]`.

/// Django's `DisallowedHost`: the host header is not a valid host name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisallowedHost;

/// `split_domain_port`: the lowercased domain (one trailing dot removed)
/// and port of a host matching
/// `^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::([0-9]+))?$`, or `None`.
#[must_use]
pub fn split_domain_port(host: &str) -> Option<(String, String)> {
    // Python's `str.lower()`; the pattern only admits ASCII afterwards.
    let lower = host.to_lowercase();
    let (domain, rest) = if let Some(inner_and_rest) = lower.strip_prefix('[') {
        let (inner, rest) = inner_and_rest.split_once(']')?;
        // `[a-f0-9]*:[a-f0-9.:]+`: a hex run, a colon, then at least one more.
        let hex_run = inner.find(|c: char| !matches!(c, 'a'..='f' | '0'..='9'))?;
        let after = inner[hex_run..].strip_prefix(':')?;
        if after.is_empty()
            || !after
                .chars()
                .all(|c| matches!(c, 'a'..='f' | '0'..='9' | '.' | ':'))
        {
            return None;
        }
        (format!("[{inner}]"), rest)
    } else {
        let end = lower
            .find(|c: char| !matches!(c, 'a'..='z' | '0'..='9' | '.' | '-'))
            .unwrap_or(lower.len());
        if end == 0 {
            return None;
        }
        (lower[..end].to_owned(), &lower[end..])
    };
    let port = match rest.strip_prefix(':') {
        None if rest.is_empty() => "",
        Some(port) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => port,
        _ => return None,
    };
    Some((
        domain.strip_suffix('.').unwrap_or(&domain).to_owned(),
        port.to_owned(),
    ))
}

/// `get_host()`: the raw host, unchanged, if its domain is valid.
///
/// # Errors
///
/// [`DisallowedHost`] for a host Django rejects.
pub fn get_host(raw_host: &str) -> Result<&str, DisallowedHost> {
    match split_domain_port(raw_host) {
        Some((domain, _)) if !domain.is_empty() => Ok(raw_host),
        _ => Err(DisallowedHost),
    }
}

/// django-tenants' `hostname_from_request`: the valid host before its first
/// `:`, without a leading `www.`.
///
/// # Errors
///
/// [`DisallowedHost`] for a host Django rejects.
pub fn tenant_hostname(raw_host: &str) -> Result<&str, DisallowedHost> {
    let host = get_host(raw_host)?;
    let name = host.split(':').next().unwrap_or_default();
    Ok(name.strip_prefix("www.").unwrap_or(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_like_django() {
        for (host, expected) in [
            ("authentik.test", Some(("authentik.test", ""))),
            ("Example.TEST:9000", Some(("example.test", "9000"))),
            ("example.test.", Some(("example.test", ""))),
            ("[::1]:443", Some(("[::1]", "443"))),
            ("[2001:db8::1]", Some(("[2001:db8::1]", ""))),
            ("[1.2:3]", None),
            ("[::]", Some(("[::]", ""))),
            ("host:", None),
            ("a_b.test", None),
            ("other.test, more.test", None),
            ("", None),
        ] {
            assert_eq!(
                split_domain_port(host),
                expected.map(|(d, p)| (d.to_owned(), p.to_owned())),
                "{host:?}"
            );
        }
        assert_eq!(get_host("."), Err(DisallowedHost));
        assert_eq!(tenant_hostname("www.Example.test:1"), Ok("Example.test"));
    }
}

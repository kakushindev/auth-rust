//! `authentik.lib.avatars.get_avatar`: the tenant's comma-separated modes,
//! first truthy answer wins, `DEFAULT_AVATAR` last.
//!
//! URL modes (`gravatar` and `…://…`) answer from Django's cache only. A
//! miss means Django would send an HTTP `HEAD` and cache the outcome, which
//! is not ported: [`resolve`] declines, and Django answers that request and
//! fills the cache. Cache writes Django makes on a hit (`touch`, expired
//! deletes) are queued in `writes` for the view to apply.

use std::fmt::Write as _;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use md5::{Digest as _, Md5};
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;

use crate::{
    Decline,
    cache::{self, PyValue, Write},
    py::strip,
};

/// `static("dist/assets/images/user_default.png")` with `web.path = "/"`.
pub const DEFAULT_AVATAR: &str = "/static/dist/assets/images/user_default.png";

const GRAVATAR_URL: &str = "https://www.gravatar.com";

const SVG_FONTS: &str = "'RedHatText','Overpass',overpass,helvetica,arial,sans-serif";

/// The user fields avatars read.
pub struct AvatarUser<'a> {
    pub username: &'a str,
    pub name: &'a str,
    pub email: &'a str,
    /// `attributes`, parsed.
    pub attributes: &'a Value,
}

fn md5_hex(text: &str) -> String {
    hex::encode(Md5::digest(text.as_bytes()))
}

/// `generate_colors`: background and text colour from `md5(text.lower())`.
fn generate_colors(text: &str) -> (String, &'static str) {
    let digest = Md5::digest(text.to_lowercase().as_bytes());
    // `int(hexdigest, 16) % 0xFFFFFF`, on the 128-bit value.
    let color = u128::from_be_bytes(digest.into()) % 0x00FF_FFFF;
    let channel =
        |shift: u32| u8::try_from(((color >> shift) & 0xFF).clamp(55, 200)).unwrap_or(200);
    let (red, green, blue) = (channel(16), channel(8), channel(0));
    // Python's plain float arithmetic, in its order (no fused multiply-add).
    #[expect(clippy::suboptimal_flops, reason = "must round like CPython")]
    let luma =
        f64::from(red) * 0.299_f64 + f64::from(green) * 0.587_f64 + f64::from(blue) * 0.114_f64;
    let text_hex = if luma > 186.0_f64 { "000" } else { "fff" };
    (format!("{red:02x}{green:02x}{blue:02x}"), text_hex)
}

/// Python `str.split()`.
fn py_split(text: &str) -> Vec<&str> {
    text.split(ak_auth::python::isspace)
        .filter(|part| !part.is_empty())
        .collect()
}

/// lxml text escaping (ASCII output); `None` for a string lxml rejects ("All strings must
/// be XML compatible"), which makes Django answer 500.
fn xml_text(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            '\t' | '\n' => out.push(c),
            c if u32::from(c) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => return None,
            // `etree.tostring` defaults to ASCII: character references.
            c if !c.is_ascii() => {
                let _ = write!(out, "&#{};", u32::from(c));
            }
            c => out.push(c),
        }
    }
    Some(out)
}

/// `generate_avatar_from_name(name)` with its defaults (two initials,
/// 64 px, square, regular weight, upper case).
fn generate_avatar_from_name(name: &str) -> Result<String, Decline> {
    let mut parts = py_split(name);
    if parts.len() > 2 {
        parts = vec![parts[0], parts[parts.len() - 1]];
    }
    let initials: String = match parts.as_slice() {
        [] => return Err(Decline("avatar name")),
        [one] => one.chars().take(2).collect(),
        [init @ .., last] => {
            let mut s: String = init.iter().filter_map(|p| p.chars().next()).collect();
            s.push_str(last);
            s.chars().take(2).collect()
        }
    };
    let (bg_hex, text_hex) = generate_colors(name);
    let text = xml_text(&initials.to_uppercase()).ok_or(Decline("avatar not XML"))?;
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64px\" height=\"64px\" viewBox=\"0 0 \
         64 64\" version=\"1.1\"><rect fill=\"#{bg_hex}\" cx=\"32\" cy=\"32\" width=\"64\" \
         height=\"64\" r=\"32\"/><text x=\"50%\" y=\"50%\" style=\"color: #{text_hex}; \
         line-height: 1; font-family: {SVG_FONTS}; \" fill=\"#{text_hex}\" \
         alignment-baseline=\"middle\" dominant-baseline=\"middle\" text-anchor=\"middle\" \
         font-size=\"28\" font-weight=\"400\" dy=\".1em\">{text}</text></svg>"
    ))
}

/// `avatar_mode_generated`.
fn mode_generated(user: &AvatarUser<'_>) -> Result<String, Decline> {
    let mut name = strip(user.name);
    if name.is_empty() {
        name = strip(user.username);
    }
    if name.is_empty() {
        name = "a k";
    }
    let svg = generate_avatar_from_name(name)?;
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg)
    ))
}

/// `avatar_mode_attribute`: `get_path_from_dict(user.attributes, path)`;
/// only dict walks and string (or falsy) results are reproduced.
fn mode_attribute(user: &AvatarUser<'_>, path: &str) -> Result<Option<String>, Decline> {
    let mut walk = user.attributes;
    for comp in path.split('.') {
        let truthy = match walk {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0_f64),
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        };
        if !truthy {
            return Ok(None);
        }
        // `comp in walk`, then `walk.get(comp)`: only a dict has `get`, so a
        // match anywhere else raises (Django 500), and a miss is the default.
        let map = match walk {
            Value::Object(map) => map,
            Value::String(text) if !text.contains(comp) => return Ok(None),
            Value::Array(items) if !items.iter().any(|i| i.as_str() == Some(comp)) => {
                return Ok(None);
            }
            _ => return Err(Decline("avatar attribute path")),
        };
        match map.get(comp) {
            Some(next) => walk = next,
            None => return Ok(None),
        }
    }
    match walk {
        Value::String(s) if !s.is_empty() => Ok(Some(s.clone())),
        Value::String(_) | Value::Null | Value::Bool(false) => Ok(None),
        Value::Number(n) if n.as_f64() == Some(0.0_f64) => Ok(None),
        Value::Array(a) if a.is_empty() => Ok(None),
        Value::Object(o) if o.is_empty() => Ok(None),
        _ => Err(Decline("avatar attribute value")),
    }
}

/// `urlparse(url).hostname` for a plain `scheme://host[:port]/…` URL.
fn hostname(url: &str) -> Result<String, Decline> {
    let rest = url.split_once("://").ok_or(Decline("avatar url"))?.1;
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = netloc.split(':').next().unwrap_or_default();
    if host.is_empty()
        || netloc.contains(['@', '[', ']'])
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(Decline("avatar url host"));
    }
    Ok(host.to_ascii_lowercase())
}

/// `avatar_mode_url` from the cache.
async fn mode_url(
    pool: &PgPool,
    now: DateTime<Utc>,
    user: &AvatarUser<'_>,
    mode: &str,
    writes: &mut Vec<Write>,
) -> Result<Option<String>, Decline> {
    let mail_hash = md5_hex(&user.email.to_lowercase());
    // `user.attributes.get("upn", "")` needs a dict.
    if !user.attributes.is_object() {
        return Err(Decline("avatar attributes"));
    }
    let upn = match user.attributes.get("upn") {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(Decline("avatar upn")),
    };
    let formatted = mode
        .replace("%(username)s", user.username)
        .replace("%(mail_hash)s", &mail_hash)
        .replace("%(upn)s", &upn);
    let host = hostname(&formatted)?;
    let available_key = format!("goauthentik.io/lib/avatars/{host}/available");
    // `cache.get(key, True)`: a missing key counts as available.
    if let Some(available) = cache::get(pool, now, &available_key, writes).await?
        && !available.truthy()
    {
        return Ok(None);
    }
    let image_key = format!("goauthentik.io/lib/avatars/{host}/{mail_hash}");
    if !cache::has_key(pool, now, &image_key).await? {
        return Err(Decline("avatar not cached"));
    }
    writes.push(Write::Touch(image_key.clone()));
    match cache::get_touched(pool, &image_key).await? {
        None | Some(PyValue::None) => Ok(None),
        Some(PyValue::Str(url)) => Ok(Some(url).filter(|u| !u.is_empty())),
        Some(PyValue::Bool(_)) => Err(Decline("avatar cache value")),
    }
}

/// `get_avatar(user, request)` for the tenant's `avatars` setting.
///
/// # Errors
///
/// A [`Decline`] whenever Django would leave the cache (an outbound check)
/// or the reproduced cases.
pub async fn resolve(
    pool: &PgPool,
    now: DateTime<Utc>,
    modes: &str,
    user: &AvatarUser<'_>,
    writes: &mut Vec<Write>,
) -> Result<String, Decline> {
    for mode in modes.split(',') {
        let avatar = match mode {
            "none" => Some(DEFAULT_AVATAR.to_owned()),
            "initials" => Some(mode_generated(user)?),
            "gravatar" => {
                let hash = hex::encode(Sha256::digest(user.email.to_lowercase().as_bytes()));
                let url = format!("{GRAVATAR_URL}/avatar/{hash}?size=158&rating=g&default=404");
                mode_url(pool, now, user, &url, writes).await?
            }
            m if m.starts_with("attributes.") => mode_attribute(user, &m[11..])?,
            m if m.contains("://") => mode_url(pool, now, user, m, writes).await?,
            _ => None,
        };
        if let Some(avatar) = avatar {
            return Ok(avatar);
        }
    }
    Ok(DEFAULT_AVATAR.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_matches_lxml() {
        // `generate_avatar_from_name('a & <b> "c"')` in the reference image.
        assert_eq!(
            generate_avatar_from_name("a & <b> \"c\"").expect("svg"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64px\" height=\"64px\" \
             viewBox=\"0 0 64 64\" version=\"1.1\"><rect fill=\"#7537a3\" cx=\"32\" cy=\"32\" \
             width=\"64\" height=\"64\" r=\"32\"/><text x=\"50%\" y=\"50%\" style=\"color: \
             #fff; line-height: 1; font-family: 'RedHatText','Overpass',overpass,helvetica,\
             arial,sans-serif; \" fill=\"#fff\" alignment-baseline=\"middle\" \
             dominant-baseline=\"middle\" text-anchor=\"middle\" font-size=\"28\" \
             font-weight=\"400\" dy=\".1em\">A\"</text></svg>"
        );
        assert_eq!(
            generate_avatar_from_name("x\u{1}y"),
            Err(Decline("avatar not XML"))
        );
    }

    #[test]
    fn hostnames_like_urlparse() {
        assert_eq!(
            hostname("https://WWW.Gravatar.com/avatar/x").expect("host"),
            "www.gravatar.com"
        );
        assert_eq!(hostname("http://h:8080?x").expect("host"), "h");
        assert_eq!(hostname("https://u@h/"), Err(Decline("avatar url host")));
    }
}

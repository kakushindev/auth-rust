//! The session middlewares for a request carrying `authentik_session`:
//! `SessionMiddleware`, `BoundSessionMiddleware`, `AuthenticationMiddleware`
//! and `ImpersonateMiddleware` (decided by [`ak_auth::session::resolve`]),
//! and `SessionMiddleware.process_response`.
//!
//! Only requests that leave the session untouched are served: Django saves
//! a session whose `last_ip` changed and flushes one whose user is inactive
//! or whose binding broke. Those writes (a re-pickled session, a logout
//! event) are declined. An empty session (expired or unknown key) gets
//! Django's cookie deletion.

use http::header;

use crate::{
    Decline,
    drf::{ApiRequest, Context, cookie_value},
};

/// `HttpRequest.is_secure()` under `SECURE_PROXY_SSL_HEADER =
/// ("HTTP_X_FORWARDED_PROTO", "https")`: the first listed value.
fn request_is_secure(req: &ApiRequest<'_>) -> bool {
    req.headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').next().unwrap_or_default().trim() == "https")
}

/// The session user and the `Set-Cookie` values `process_response` adds.
///
/// # Errors
///
/// A [`Decline`] for every path that writes, or that is not reproduced.
pub(crate) async fn middleware(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
) -> Result<(Option<ak_auth::session::RequestUser>, Vec<String>), Decline> {
    let Some(cookie) = cookie_value(req.headers, ak_auth::session::SESSION_COOKIE_NAME)? else {
        return Ok((None, Vec::new()));
    };
    let settings = ctx.sessions.ok_or(Decline("sessions not configured"))?;
    // `ClientIPMiddleware` with an outpost's delegated IP looks the token
    // up (deleting it when expired).
    if req.headers.contains_key("x-authentik-outpost-token") {
        return Err(Decline("outpost client ip"));
    }
    let forwarded_for = req
        .headers
        .get("x-forwarded-for")
        .map(|v| v.to_str().map_err(|_| Decline("x-forwarded-for bytes")))
        .transpose()?
        .ok_or(Decline("no x-forwarded-for"))?;
    let client_ip = ak_auth::client_ip::from_meta(Some(forwarded_for), None);
    let resolved = ak_auth::session::resolve(
        ctx.pool,
        Some(&cookie),
        &client_ip,
        ctx.secret_key,
        &settings.geoip,
        settings.cookie_age,
        ctx.now,
    )
    .await
    .map_err(|_| Decline("session middleware raised"))?;
    match resolved.user {
        ak_auth::session::RequestUser::InactiveLogout => return Err(Decline("inactive logout")),
        ak_auth::session::RequestUser::BindingBroken(_) => return Err(Decline("binding broken")),
        _ => {}
    }
    if resolved.set_last_ip.is_some() {
        return Err(Decline("session modified"));
    }
    let cookies = if resolved.session_key.is_none() {
        let host = req.headers.get(header::HOST).and_then(|v| v.to_str().ok());
        let user_agent = req
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let secure = ak_auth::cookie::session_is_secure(
            request_is_secure(req),
            host,
            settings.debug,
            user_agent,
        );
        #[expect(
            clippy::as_conversions,
            clippy::cast_precision_loss,
            reason = "epoch seconds"
        )]
        let now = ctx.now.timestamp_micros() as f64 / 1e6_f64;
        let effect = ak_auth::cookie::session_process_response(
            &ak_auth::cookie::SessionResponse {
                had_cookie: true,
                accessed: true,
                modified: false,
                empty: true,
                session_key: None,
                user_uid: None,
                expiry_age: None,
                status: 200,
                secure,
                web_path: "/",
                cookie_domain: settings.cookie_domain.as_deref(),
            },
            ctx.secret_key,
            now,
        )
        .map_err(|_| Decline("cookie rendering"))?;
        effect.cookies
    } else {
        Vec::new()
    };
    Ok((Some(resolved.user), cookies))
}

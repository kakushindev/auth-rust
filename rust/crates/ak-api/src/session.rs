//! The session middlewares for a request carrying `authentik_session`:
//! `SessionMiddleware`, `BoundSessionMiddleware`, `AuthenticationMiddleware`
//! and `ImpersonateMiddleware` (decided by [`ak_auth::session::resolve`]),
//! and `SessionMiddleware.process_response`.
//!
//! A session whose only change is `last_ip` is saved as Django saves it
//! ([`ak_auth::session::SessionSave`]) and its cookie refreshed. Flushes
//! (an inactive user, a broken binding: logout and event) are declined.
//! An empty session (expired or unknown key) gets Django's cookie
//! deletion.

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

/// What the session middlewares decided before the view.
#[derive(Default)]
pub(crate) struct State {
    pub user: Option<ak_auth::session::RequestUser>,
    /// `Set-Cookie` values that do not depend on the view (a deletion).
    pub cookies: Vec<String>,
    /// A modified session to save after the view.
    save: Option<Save>,
}

struct Save {
    plan: ak_auth::session::SessionSave,
    expiry_age: Option<f64>,
    secure: bool,
}

fn now_seconds(ctx: &Context<'_>) -> f64 {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "epoch seconds"
    )]
    let now = ctx.now.timestamp_micros() as f64 / 1e6_f64;
    now
}

/// `SessionMiddleware.process_response` for a modified session: the
/// refreshed cookie (rendered first), then `request.session.save()`.
/// Skipped on a 500, as Django does.
///
/// # Errors
///
/// A [`Decline`] before anything is written: no recorded DRF user, a cookie
/// that cannot be rendered, or a session deleted meanwhile (Django's
/// `SessionInterrupted`).
pub(crate) async fn finish(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    state: State,
    status: u16,
) -> Result<Vec<String>, Decline> {
    let Some(save) = state.save else {
        return Ok(state.cookies);
    };
    if status == 500 {
        return Ok(state.cookies);
    }
    let user = req
        .drf_user
        .lock()
        .ok()
        .and_then(|cell| *cell)
        .ok_or(Decline("no drf user"))?;
    let uid = match user {
        Some(id) => {
            let install_id = ak_auth::session::install_id(ctx.pool)
                .await
                .map_err(|_| Decline("database error"))?;
            Some(ak_auth::cookie::user_uid(id, &install_id))
        }
        None => None,
    };
    let effect = ak_auth::cookie::session_process_response(
        &ak_auth::cookie::SessionResponse {
            had_cookie: true,
            accessed: true,
            modified: true,
            empty: false,
            session_key: Some(&save.plan.session_key),
            user_uid: uid.as_deref(),
            expiry_age: save.expiry_age,
            status,
            secure: save.secure,
            web_path: "/",
            cookie_domain: ctx.sessions.and_then(|s| s.cookie_domain.as_deref()),
        },
        ctx.secret_key,
        now_seconds(ctx),
    )
    .map_err(|_| Decline("cookie rendering"))?;
    let rows = ak_auth::session::save_last_ip(ctx.pool, &save.plan, ctx.now)
        .await
        .map_err(|_| Decline("session save failed"))?;
    if rows == 0 {
        return Err(Decline("session deleted meanwhile"));
    }
    Ok(effect.cookies)
}

/// The session user and what `process_response` will need.
///
/// # Errors
///
/// A [`Decline`] for every path that is not reproduced.
pub(crate) async fn middleware(ctx: &Context<'_>, req: &ApiRequest<'_>) -> Result<State, Decline> {
    let Some(cookie) = cookie_value(req.headers, ak_auth::session::SESSION_COOKIE_NAME)? else {
        return Ok(State::default());
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
    let save = match (&resolved.set_last_ip, resolved.save) {
        (None, _) => None,
        (Some(_), None) => return Err(Decline("session save not reproduced")),
        (Some(_), Some(plan)) => Some(Save {
            plan,
            expiry_age: resolved.expiry_age,
            secure,
        }),
    };
    let cookies = if resolved.session_key.is_none() {
        let now = now_seconds(ctx);
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
    Ok(State {
        user: Some(resolved.user),
        cookies,
        save,
    })
}

//! The session middlewares for a request carrying `authentik_session`:
//! `SessionMiddleware`, `BoundSessionMiddleware`, `AuthenticationMiddleware`
//! and `ImpersonateMiddleware` (decided by [`ak_auth::session::resolve`]),
//! and `SessionMiddleware.process_response`.
//!
//! A session whose only change is `last_ip` is saved as Django saves it
//! ([`ak_auth::session::SessionSave`]) and its cookie refreshed. The
//! middlewares' logouts (an inactive user: 400; a broken binding: a
//! redirect to login) are written by [`ak_events::logout`] and answered
//! before the view, as Django answers them; one whose signal receivers are
//! not reproduced is declined. An empty session (expired or unknown key)
//! gets Django's cookie deletion.

use http::header;

use crate::{
    Answer, Decline,
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
    /// The middleware's own response (a logout), answered without the view.
    pub early: Option<Answer>,
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
    if matches!(
        resolved.user,
        ak_auth::session::RequestUser::InactiveLogout
            | ak_auth::session::RequestUser::BindingBroken(_)
    ) {
        let answer = logout(ctx, req, settings, &resolved, &client_ip, secure).await?;
        return Ok(State {
            early: Some(answer),
            ..State::default()
        });
    }
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
        early: None,
    })
}

/// The request's tenant for the logout's event and tasks: the public one.
async fn public_tenant(ctx: &Context<'_>, req: &ApiRequest<'_>) -> Result<uuid::Uuid, Decline> {
    let raw_host = req
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or(Decline("no host"))?;
    let hostname =
        ak_auth::host::tenant_hostname(raw_host).map_err(|_| Decline("disallowed host"))?;
    let tenant = ak_auth::tenant::resolve(ctx.pool, hostname)
        .await
        .map_err(|_| Decline("database error"))?
        .ok_or(Decline("no tenant"))?;
    let schema: Option<String> = sqlx::query_scalar(
        "SELECT schema_name FROM authentik_tenants_tenant WHERE tenant_uuid = $1",
    )
    .bind(tenant)
    .fetch_optional(ctx.pool)
    .await
    .map_err(|_| Decline("database error"))?;
    if schema.as_deref() != Some("public") {
        return Err(Decline("tenant"));
    }
    Ok(tenant)
}

/// `AuthenticationMiddleware`'s 400 for an inactive user, or
/// `BoundSessionMiddleware`'s redirect to login, after the logout and the
/// flush; `SessionMiddleware.process_response` then deletes the cookie.
/// `LocaleMiddleware` sits between the two, so only the 400 has its
/// `Content-Language` and `Accept-Language` vary.
async fn logout(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    settings: &crate::SessionSettings,
    resolved: &ak_auth::session::Resolved,
    client_ip: &str,
    secure: bool,
) -> Result<Answer, Decline> {
    let flush = resolved
        .flush
        .as_ref()
        .ok_or(Decline("logout without a session"))?;
    let tenant = public_tenant(ctx, req).await?;
    // `META["HTTP_USER_AGENT"]`: the header's bytes as Latin-1.
    let user_agent: String = req
        .headers
        .get(header::USER_AGENT)
        .map(|v| v.as_bytes().iter().copied().map(char::from).collect())
        .unwrap_or_default();
    let mut tx = ctx
        .pool
        .begin()
        .await
        .map_err(|_| Decline("database error"))?;
    let written = ak_events::logout::logout(
        &mut tx,
        tenant,
        flush,
        &ak_events::logout::Request {
            path: req.path,
            method: "GET",
            query_string: req.query,
            user_agent: &user_agent,
            client_ip,
        },
        &settings.geoip,
        ctx.now,
    )
    .await;
    if written.is_err() {
        let _ = tx.rollback().await;
        return Err(Decline("logout not reproduced"));
    }
    let effect = ak_auth::cookie::session_process_response(
        &ak_auth::cookie::SessionResponse {
            had_cookie: true,
            accessed: true,
            modified: false,
            empty: true,
            session_key: None,
            user_uid: None,
            expiry_age: None,
            status: 400,
            secure,
            web_path: "/",
            cookie_domain: settings.cookie_domain.as_deref(),
        },
        ctx.secret_key,
        now_seconds(ctx),
    )
    .map_err(|_| Decline("cookie rendering"))?;
    tx.commit().await.map_err(|_| Decline("database error"))?;
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    let status = if matches!(resolved.user, ak_auth::session::RequestUser::InactiveLogout) {
        headers.push(("content-language", "en".to_owned()));
        headers.push(("content-type", "text/html; charset=utf-8".to_owned()));
        headers.push(("vary", "Accept-Language, Cookie".to_owned()));
        400
    } else {
        let path = ak_auth::url::request_path(req.path);
        let next = ak_auth::url::get_full_path(&path, req.query);
        headers.push(("content-type", "text/html; charset=utf-8".to_owned()));
        headers.push(("location", ak_auth::url::login_redirect("/", &next)));
        headers.push(("vary", "Cookie".to_owned()));
        302
    };
    headers.extend(effect.cookies.into_iter().map(|c| ("set-cookie", c)));
    Ok(Answer {
        status,
        headers,
        body: Vec::new(),
    })
}

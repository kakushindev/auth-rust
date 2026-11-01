//! The logouts the session middlewares perform: `AuthenticationMiddleware`
//! logging out an inactive user (`django.contrib.auth.logout`) and
//! `BoundSessionMiddleware.logout_extra` for a broken binding.
//!
//! Both send `user_logged_out` once and flush the session. The signal's
//! receivers are the events app's `on_user_logged_out` (a `logout` event,
//! its context updated with the binding's `to_event()`) and the SAML
//! source's, which deletes users flagged `delete-on-logout`. The flush
//! deletes the `Session`, which cascades to its `AuthenticatedSession`,
//! whose `pre_delete` receivers are RAC (a channel-layer disconnect), `OAuth2`
//! (revoke tokens, back-channel logout), SAML (back-channel logout tasks),
//! outposts (`outpost_session_end` when any outpost exists) and SSF.
//!
//! Reproduced: the events, the outpost task and the deletions. Declined,
//! before anything is written, when another receiver would act: a
//! `delete-on-logout` user, rows depending on the `AuthenticatedSession`
//! (`OAuth2` tokens and codes, SAML sessions, RAC connection tokens), a
//! connected RAC client, or any SSF stream.

use ak_auth::{binding::GeoIp, session::Flush};
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    Error,
    event::{self, Action, HttpRequest, SessionUsers, UserRef},
    task,
};

/// `USER_ATTRIBUTE_DELETE_ON_LOGOUT`.
const DELETE_ON_LOGOUT: &str = "goauthentik.io/user/delete-on-logout";
/// Tables whose rows depend on an `AuthenticatedSession`.
const DEPENDENTS: [&str; 6] = [
    "authentik_providers_oauth2_authorizationcode",
    "authentik_providers_oauth2_refreshtoken",
    "authentik_providers_oauth2_devicetoken",
    "authentik_providers_oauth2_accesstoken",
    "authentik_providers_saml_samlsession",
    "authentik_providers_rac_connectiontoken",
];

/// What the request contributes to the logout event: the middlewares
/// after the session ones (brand, request id) have not run.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub query_string: &'a str,
    pub user_agent: &'a str,
    pub client_ip: &'a str,
}

/// What a logout wrote.
#[derive(Debug, Clone)]
pub struct Written {
    pub events: Vec<event::Written>,
    /// `outpost_session_end`, when the session was authenticated and an
    /// outpost exists.
    pub outpost_task: Option<Uuid>,
}

/// The SAML source's receiver: is the user flagged for deletion?
async fn delete_on_logout(conn: &mut PgConnection, user: i32) -> Result<bool, Error> {
    // Python truthiness of the attribute (`attributes.get(..., False)`).
    let flagged: Option<bool> = sqlx::query_scalar(
        "SELECT CASE jsonb_typeof(attributes -> $2) WHEN 'boolean' THEN (attributes ->> \
         $2)::boolean WHEN 'null' THEN false WHEN 'string' THEN attributes ->> $2 <> '' WHEN \
         'number' THEN (attributes ->> $2)::numeric <> 0 WHEN 'array' THEN \
         jsonb_array_length(attributes -> $2) > 0 WHEN 'object' THEN attributes -> $2 <> \
         '{}'::jsonb ELSE false END FROM authentik_core_user WHERE id = $1",
    )
    .bind(user)
    .bind(DELETE_ON_LOGOUT)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    Ok(flagged.unwrap_or(false))
}

/// Declines the cascade's receivers that are not reproduced.
async fn check_cascade(
    conn: &mut PgConnection,
    tenant: Uuid,
    session_key: &str,
) -> Result<(), Error> {
    for table in DEPENDENTS {
        let found: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE session_id = $1)"
        )))
        .bind(session_key)
        .fetch_one(&mut *conn)
        .await?;
        if found {
            return Err(Error::Unsupported(
                "rows depend on the authenticated session",
            ));
        }
    }
    // RAC's `group_send` to `build_rac_client_group_session(session_key)`.
    let schema: String = sqlx::query_scalar(
        "SELECT schema_name FROM authentik_tenants_tenant WHERE tenant_uuid = $1",
    )
    .bind(tenant)
    .fetch_one(&mut *conn)
    .await?;
    let group = Sha256::digest(format!("{schema}/group_rac_client_{session_key}").as_bytes())
        .iter()
        .fold(String::from("asgi.group."), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        });
    let connected: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM django_channels_postgres_groupchannel WHERE group_key = $1)",
    )
    .bind(&group)
    .fetch_one(&mut *conn)
    .await?;
    if connected {
        return Err(Error::Unsupported("a RAC client is connected"));
    }
    let streams: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM authentik_providers_ssf_stream)")
            .fetch_one(&mut *conn)
            .await?;
    if streams {
        return Err(Error::Unsupported("SSF streams exist"));
    }
    Ok(())
}

/// One `on_user_logged_out` event.
#[expect(clippy::too_many_arguments, reason = "the event's inputs")]
async fn logout_event(
    conn: &mut PgConnection,
    tenant: Uuid,
    req: &Request<'_>,
    request_user: UserRef,
    user: Option<UserRef>,
    session: SessionUsers,
    extra: Option<serde_json::Map<String, serde_json::Value>>,
    geoip: &GeoIp,
    now: DateTime<Utc>,
) -> Result<event::Written, Error> {
    if let Some(UserRef::Id(id)) = &user
        && delete_on_logout(conn, *id).await?
    {
        return Err(Error::Unsupported("delete-on-logout user"));
    }
    let request = HttpRequest {
        path: req.path,
        method: req.method,
        query_string: req.query_string,
        user_agent: req.user_agent,
        request_id: None,
        brand: None,
        user: Some(request_user),
        session: Some(session),
        client_ip: req.client_ip,
    };
    event::new_from_http(
        conn,
        tenant,
        Action::Known("logout"),
        "authentik.events.signals",
        serde_json::Map::new(),
        extra,
        Some(&request),
        user.as_ref(),
        geoip,
        now,
    )
    .await
}

/// Log the session's user out and flush the session, as the middleware
/// does for `flush`, inside the caller's transaction.
///
/// # Errors
///
/// [`Error::Unsupported`] (decline; nothing written yet that the caller
/// commits) or a database error.
pub async fn logout(
    conn: &mut PgConnection,
    tenant: Uuid,
    flush: &Flush,
    req: &Request<'_>,
    geoip: &GeoIp,
    now: DateTime<Utc>,
) -> Result<Written, Error> {
    let session = {
        let data = ak_pickle::loads(&flush.session_data)
            .map_err(|_| Error::Unsupported("session pickle"))?;
        SessionUsers::from_session(&data)?
    };
    if flush.user.is_some() {
        check_cascade(conn, tenant, &flush.session_key).await?;
    }
    let mut events = Vec::new();
    match (&flush.event_extra, flush.user) {
        // `AuthenticationMiddleware`: `logout(request)` for the inactive user.
        (None, Some((id, _))) => {
            events.push(
                logout_event(
                    conn,
                    tenant,
                    req,
                    UserRef::Id(id),
                    Some(UserRef::Id(id)),
                    session,
                    None,
                    geoip,
                    now,
                )
                .await?,
            );
        }
        (None, None) => return Err(Error::Unsupported("logout without a user")),
        // `logout_extra`. `BoundSessionMiddleware` runs Django's own
        // `AuthenticationMiddleware`, which only sets `request.user`
        // lazily: Django's `get_user` finds no `_auth_user_id` (authentik
        // does not store it), so `request.user` is `AnonymousUser`, and the
        // signal's user is the `AuthenticatedSession`'s, active or not.
        (Some(extra), user) => {
            events.push(
                logout_event(
                    conn,
                    tenant,
                    req,
                    UserRef::Anonymous,
                    user.map(|(id, _)| UserRef::Id(id)),
                    session,
                    Some(extra.clone()),
                    geoip,
                    now,
                )
                .await?,
            );
        }
    }
    // The flush: `Session.delete()` cascades to the `AuthenticatedSession`.
    let mut outpost_task = None;
    if flush.user.is_some() {
        let outposts: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM authentik_outposts_outpost)")
                .fetch_one(&mut *conn)
                .await?;
        if outposts {
            outpost_task = Some(
                task::enqueue(
                    conn,
                    tenant,
                    "authentik.outposts.tasks.outpost_session_end",
                    vec![ak_pickle::write::Obj::str(&flush.session_key)],
                    now,
                )
                .await?,
            );
        }
        sqlx::query("DELETE FROM authentik_core_authenticatedsession WHERE session_id = $1")
            .bind(&flush.session_key)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("DELETE FROM authentik_core_session WHERE session_key = $1")
        .bind(&flush.session_key)
        .execute(&mut *conn)
        .await?;
    Ok(Written {
        events,
        outpost_task,
    })
}

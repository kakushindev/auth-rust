//! authentik's write-side side effects (M8): dramatiq tasks enqueued on
//! the Postgres broker, and audit events. Each writer names the Django
//! code it reproduces and is checked against the reference's rows.

pub mod event;
pub mod logout;
pub mod task;

/// Why a side effect could not be written as Django writes it.
#[derive(Debug)]
pub enum Error {
    Database(sqlx::Error),
    /// A value this port does not reproduce (the caller declines).
    Unsupported(&'static str),
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// `django.__version__` of the pinned reference, which every pickled model
/// instance records (`_django_version`).
pub const DJANGO_VERSION: &str = "5.2.17";

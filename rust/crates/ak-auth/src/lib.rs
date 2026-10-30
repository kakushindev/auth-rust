//! Request identity for authentik 2026.2.7 (milestone M5): which host,
//! brand and tenant a request belongs to, and who its bearer credential
//! authenticates.
//!
//! Each function makes the same decision as the Django code it names, using
//! Django's own SQL where Django queries, and is checked against Django by
//! `tests/auth/run.sh`. Side effects Django performs along the way (deleting
//! expired tokens, creating an outpost's service user) belong to the write
//! layer (M8) and are not done here; see each function.

pub mod brand;
pub mod host;
pub mod tenant;
pub mod token;

//! authentik-rs: brand certificates as 2026.2.7's Go server picks them
//! (`internal/web/brand_tls` with `internal/outpost/ak.CryptoStore`).
//!
//! Go lists brands through the API (ordered by `domain`) and fetches each
//! referenced keypair's certificate and key. This reads the same rows. The
//! store keeps a keypair until its stored `fingerprint_sha256` changes,
//! never loads one whose stored fingerprint is empty, and keeps the
//! previous entry when a changed one fails to load, as `CryptoStore` does.

use std::{collections::HashMap, sync::Arc};

use ak_common::db;
use eyre::{Result, eyre};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject as _, SectionKind},
    },
    sign::CertifiedKey,
};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct Brand {
    domain: String,
    default: bool,
    web_certificate: Option<Uuid>,
    client_certificates: Vec<Uuid>,
}

#[derive(Debug, Clone)]
struct Keypair {
    /// The stored `fingerprint_sha256` this entry was loaded at.
    fingerprint: String,
    /// `None` for a keypair without a private key (`key_data` empty).
    key: Option<Arc<CertifiedKey>>,
    leaf: CertificateDer<'static>,
}

/// The web certificate for a connection.
#[derive(Debug)]
pub(crate) enum WebCertificate {
    /// The self-signed default certificate.
    Fallback,
    Keypair(Arc<CertifiedKey>),
    /// The brand's keypair has no private key; Go's handshake then fails.
    NoPrivateKey,
}

#[derive(Debug)]
pub(crate) struct Selection {
    pub(crate) web: WebCertificate,
    /// Client certificate CAs to request with (`RequestClientCert`), when
    /// the brand has client certificates.
    pub(crate) client_cas: Option<Vec<CertificateDer<'static>>>,
}

/// `brand_tls.Watcher` state.
#[derive(Debug, Default)]
pub(crate) struct BrandTls {
    brands: Vec<Brand>,
    store: HashMap<Uuid, Keypair>,
}

impl BrandTls {
    /// `Watcher.GetCertificate`. Every brand is a candidate: the generated Go
    /// client marks `web_certificate` as set even when it is `null`, so the
    /// "no certificates" skip never applies. The last default brand, then
    /// the last brand whose domain is a plain suffix of the SNI, wins, in
    /// `domain` order.
    pub(crate) fn select(&self, server_name: &str) -> Selection {
        let mut best = None;
        for brand in &self.brands {
            if brand.default {
                best = Some(brand);
            }
            if server_name.ends_with(&brand.domain) {
                best = Some(brand);
            }
        }
        let Some(best) = best else {
            return Selection {
                web: WebCertificate::Fallback,
                client_cas: None,
            };
        };
        let web = match best.web_certificate.and_then(|kp| self.store.get(&kp)) {
            Some(Keypair { key: Some(key), .. }) => WebCertificate::Keypair(Arc::clone(key)),
            Some(Keypair { key: None, .. }) => WebCertificate::NoPrivateKey,
            None => WebCertificate::Fallback,
        };
        let client_cas = (!best.client_certificates.is_empty()).then(|| {
            best.client_certificates
                .iter()
                .filter_map(|kp| self.store.get(kp))
                .map(|kp| kp.leaf.clone())
                .collect()
        });
        Selection { web, client_cas }
    }

    /// `Watcher.Check`: reload the brands and their keypairs. On a database
    /// error the caller keeps the previous state, as Go keeps its brands.
    pub(crate) async fn check(&self) -> Result<Self> {
        #[derive(sqlx::FromRow)]
        struct BrandRow {
            brand_uuid: Uuid,
            domain: String,
            default: bool,
            web_certificate_id: Option<Uuid>,
        }
        #[derive(sqlx::FromRow)]
        struct ClientCertificateRow {
            brand_id: Uuid,
            certificatekeypair_id: Uuid,
        }
        #[derive(sqlx::FromRow)]
        struct KeypairRow {
            kp_uuid: Uuid,
            certificate_data: String,
            key_data: String,
            fingerprint_sha256: Option<String>,
        }

        info!("updating brand certificates");
        // BrandViewSet: `ordering = ["domain"]`.
        let brand_rows = sqlx::query_as::<_, BrandRow>(
            r#"SELECT brand_uuid, domain, "default", web_certificate_id
               FROM authentik_brands_brand ORDER BY domain"#,
        )
        .fetch_all(db::get())
        .await?;
        let client_rows = sqlx::query_as::<_, ClientCertificateRow>(
            "SELECT brand_id, certificatekeypair_id
             FROM authentik_brands_brand_client_certificates ORDER BY id",
        )
        .fetch_all(db::get())
        .await?;

        let mut clients: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in client_rows {
            clients
                .entry(row.brand_id)
                .or_default()
                .push(row.certificatekeypair_id);
        }
        let brands: Vec<Brand> = brand_rows
            .into_iter()
            .map(|row| Brand {
                domain: row.domain,
                default: row.default,
                web_certificate: row.web_certificate_id,
                client_certificates: clients.remove(&row.brand_uuid).unwrap_or_default(),
            })
            .collect();

        let referenced: Vec<Uuid> = brands
            .iter()
            .flat_map(|b| b.web_certificate.iter().chain(&b.client_certificates))
            .copied()
            .collect();
        let keypair_rows = sqlx::query_as::<_, KeypairRow>(
            "SELECT kp_uuid, certificate_data, key_data, fingerprint_sha256
             FROM authentik_crypto_certificatekeypair WHERE kp_uuid = ANY($1)",
        )
        .bind(&referenced)
        .fetch_all(db::get())
        .await?;

        let previous = self.store.clone();
        let store = tokio::task::spawn_blocking(move || {
            let mut store = previous;
            for row in keypair_rows {
                // `getFingerprint` reads the stored `fingerprint_sha256`. An
                // empty one compares equal to the reset "" and Go keeps
                // whatever it has, so such a keypair is never loaded.
                let Some(fingerprint) = row.fingerprint_sha256.filter(|f| !f.is_empty()) else {
                    continue;
                };
                if store
                    .get(&row.kp_uuid)
                    .is_some_and(|kp| kp.fingerprint == fingerprint)
                {
                    continue;
                }
                info!(uuid = %row.kp_uuid, "Fetching certificate and private key");
                match load_keypair(&row.certificate_data, &row.key_data) {
                    Ok((key, leaf)) => {
                        store.insert(
                            row.kp_uuid,
                            Keypair {
                                fingerprint,
                                key,
                                leaf,
                            },
                        );
                    }
                    Err(err) => {
                        warn!(?err, kp = %row.kp_uuid, "failed to add certificate");
                    }
                }
            }
            store
        })
        .await?;

        Ok(Self { brands, store })
    }
}

/// `CryptoStore.Fetch`: with a key, `tls.X509KeyPair` (every certificate
/// block, the first private key, which must match the leaf); without one,
/// the first PEM block must be the certificate.
fn load_keypair(
    certificate_data: &str,
    key_data: &str,
) -> Result<(Option<Arc<CertifiedKey>>, CertificateDer<'static>)> {
    if key_data.is_empty() {
        let (kind, der) =
            pem::from_buf(&mut certificate_data.as_bytes())?.ok_or_else(|| eyre!("no PEM data"))?;
        if kind != SectionKind::Certificate {
            return Err(eyre!("first PEM block is not a certificate"));
        }
        return Ok((None, CertificateDer::from(der)));
    }
    let chain = CertificateDer::pem_slice_iter(certificate_data.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = chain
        .first()
        .cloned()
        .ok_or_else(|| eyre!("no certificate"))?;
    let key = PrivateKeyDer::from_pem_slice(key_data.as_bytes())?;
    let provider = CryptoProvider::get_default().ok_or_else(|| eyre!("no rustls provider"))?;
    let certified = CertifiedKey::from_der(chain, key, provider)?;
    Ok((Some(Arc::new(certified)), leaf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PEM text, as authentik stores keypairs.
    fn to_pem(label: &str, der: &[u8]) -> String {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    fn generate_pem() -> (String, String) {
        let (cert, key) = ak_common::tls::self_signed::generate().expect("generate");
        (
            to_pem("CERTIFICATE", cert.der()),
            to_pem("PRIVATE KEY", &key.serialize_der()),
        )
    }

    fn brand(domain: &str, default: bool, web: Option<Uuid>) -> Brand {
        Brand {
            domain: domain.to_owned(),
            default,
            web_certificate: web,
            client_certificates: Vec::new(),
        }
    }

    fn keypair() -> Keypair {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert, key) = generate_pem();
        let (key, leaf) = load_keypair(&cert, &key).expect("load");
        Keypair {
            fingerprint: String::new(),
            key,
            leaf,
        }
    }

    fn web(selection: &Selection) -> Option<&Arc<CertifiedKey>> {
        match &selection.web {
            WebCertificate::Keypair(key) => Some(key),
            _ => None,
        }
    }

    #[test]
    fn selection_follows_go() {
        let (a, default, example) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let store: HashMap<Uuid, Keypair> =
            [(a, keypair()), (default, keypair()), (example, keypair())].into();
        let key = |kp: &Uuid| store[kp].key.clone().expect("has key");
        let state = BrandTls {
            brands: vec![
                brand("a.test", false, Some(a)),
                brand("authentik-default", true, Some(default)),
                brand("example.com", false, Some(example)),
                brand("unloaded.test", false, Some(Uuid::new_v4())),
            ],
            store: store.clone(),
        };
        let picks = |sni: &str| web(&state.select(sni)).cloned();
        // No SNI picks the default brand.
        assert!(Arc::ptr_eq(&picks("").expect("cert"), &key(&default)));
        // Plain suffix, no dot boundary.
        assert!(Arc::ptr_eq(
            &picks("notexample.com").expect("cert"),
            &key(&example)
        ));
        // The default brand comes later in domain order than a.test, but a
        // suffix match on a.test was earlier, so the later default wins.
        assert!(Arc::ptr_eq(
            &picks("x.a.test").expect("cert"),
            &key(&default)
        ));
        // A selected brand whose keypair is not loaded uses the fallback.
        assert!(matches!(
            state.select("unloaded.test").web,
            WebCertificate::Fallback
        ));
        // No brands at all: fallback, no client CAs.
        let empty = BrandTls::default().select("example.com");
        assert!(matches!(empty.web, WebCertificate::Fallback) && empty.client_cas.is_none());
    }

    #[test]
    fn client_cas_from_selected_brand() {
        let (ca, missing) = (Uuid::new_v4(), Uuid::new_v4());
        let ca_keypair = keypair();
        let mut with_clients = brand("clients.test", false, None);
        with_clients.client_certificates = vec![ca, missing];
        let state = BrandTls {
            brands: vec![with_clients],
            store: [(ca, ca_keypair.clone())].into(),
        };
        let selection = state.select("clients.test");
        assert!(matches!(selection.web, WebCertificate::Fallback));
        assert_eq!(selection.client_cas, Some(vec![ca_keypair.leaf]));
        assert_eq!(state.select("other.test").client_cas, None);
    }

    #[test]
    fn keypair_without_key_is_certificate_only() {
        let (cert, _) = generate_pem();
        let (key, leaf) = load_keypair(&cert, "").expect("load");
        assert!(key.is_none());
        assert_eq!(
            Some(leaf),
            CertificateDer::pem_slice_iter(cert.as_bytes())
                .next()
                .and_then(Result::ok)
        );
        let _err = load_keypair("garbage", "").expect_err("not PEM");
    }

    #[test]
    fn keypair_key_must_match() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert, key) = generate_pem();
        let (_, other) = generate_pem();
        load_keypair(&cert, &key).expect("matching key");
        let _err = load_keypair(&cert, &other).expect_err("key of another certificate");
    }
}

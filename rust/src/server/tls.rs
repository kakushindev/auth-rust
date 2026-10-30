//! authentik-rs: the HTTPS listener as 2026.2.7's Go server configures it
//! (`internal/web/web_tls.go` `GetCertificate`, which is a
//! `GetConfigForClient`, and `internal/utils.GetTLSConfig`).
//!
//! Each connection gets its own configuration from its `ClientHello`: the
//! embedded outpost's application certificate for the SNI if it has one,
//! else the brand selection (`brands::tls`), else the self-signed default.
//! A brand with client certificates requests one (`RequestClientCert`):
//! the certificate is passed on to Django but its chain is not verified.

use std::{
    env,
    sync::{Arc, LazyLock},
    time::Duration,
};

use ak_axum::accept::tls::ConfigForHello;
use ak_common::{Arbiter, Event};
use eyre::Result;
use rustls::{
    CipherSuite, DigitallySignedStruct, DistinguishedName, NamedGroup, RootCertStore, ServerConfig,
    SignatureAlgorithm, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs, verify_tls12_signature,
        verify_tls13_signature,
    },
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime},
    server::{
        ClientHello, ProducesTickets, ResolvesServerCert, StoresServerSessions,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, Signer, SigningKey},
};
use tracing::{debug, info, trace, warn};

use crate::{brands::tls::WebCertificate, server::Server};

/// `GetTLSConfig`'s suites as Go 1.25.5 applies them, in Go's preference
/// order (AES-128 before AES-256; Go picks the server's order). With
/// `GOFIPS=1`, as the 2026.2.7 image sets it, Go drops `ChaCha20` from TLS 1.3
/// and X25519 from the groups. TLS 1.2 CBC and RSA key exchange suites,
/// which Go also offers outside FIPS mode, do not exist in rustls.
fn go_provider() -> CryptoProvider {
    let fips = env::var("GOFIPS").is_ok_and(|v| v == "1");
    let mut suites = vec![
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
    ];
    if !fips {
        suites.push(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    }
    suites.extend([
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]);
    let mut groups = Vec::new();
    if !fips {
        groups.push(NamedGroup::X25519);
    }
    groups.extend([NamedGroup::secp256r1, NamedGroup::secp384r1]);

    let base = aws_lc_rs::default_provider();
    CryptoProvider {
        cipher_suites: suites
            .iter()
            .filter_map(|id| {
                base.cipher_suites
                    .iter()
                    .find(|s| s.suite() == *id)
                    .copied()
            })
            .collect(),
        kx_groups: groups
            .iter()
            .filter_map(|id| base.kx_groups.iter().find(|g| g.name() == *id).copied())
            .collect(),
        ..base
    }
}

static GO_PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| Arc::new(go_provider()));

/// Go 1.25.5's signature scheme preference
/// (`defaultSupportedSignatureAlgorithms`, without SHA-1). Go signs with the
/// first one the peer offers that the key supports, and requests client
/// certificate signatures in this order.
const GO_SIGNATURE_SCHEMES: [SignatureScheme; 10] = [
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

/// A signing key choosing its scheme in Go's preference order rather than
/// rustls's (which prefers SHA-512).
#[derive(Debug)]
struct GoSigningKey(Arc<dyn SigningKey>);

impl SigningKey for GoSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        GO_SIGNATURE_SCHEMES
            .iter()
            .filter(|scheme| offered.contains(scheme))
            .find_map(|scheme| self.0.choose_scheme(&[*scheme]))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

fn go_signing(key: &CertifiedKey) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey {
        cert: key.cert.clone(),
        key: Arc::new(GoSigningKey(Arc::clone(&key.key))),
        ocsp: key.ocsp.clone(),
    })
}

/// Go's session ticket lifetime hint (`maxSessionTicketLifetime`, 7 days).
const TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;

/// rustls's rotating ticketer, advertising Go's lifetime hint: 7 days in
/// TLS 1.3, none (0) in TLS 1.2. rustls only uses the lifetime as that hint.
/// Keys still rotate every 6 hours (one previous key kept), so a ticket older
/// than about 12 hours falls back to a full handshake where Go would resume.
#[derive(Debug)]
struct GoTicketer {
    inner: Arc<dyn ProducesTickets>,
    lifetime: u32,
}

impl ProducesTickets for GoTicketer {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.inner.encrypt(plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.inner.decrypt(cipher)
    }
}

/// Go keeps one set of session ticket keys for every config returned by
/// `GetConfigForClient`; so do these (TLS 1.3, TLS 1.2 hint).
static TICKETERS: LazyLock<Option<[Arc<dyn ProducesTickets>; 2]>> = LazyLock::new(|| {
    let inner = aws_lc_rs::Ticketer::new().ok()?;
    let with = |lifetime| -> Arc<dyn ProducesTickets> {
        Arc::new(GoTicketer {
            inner: Arc::clone(&inner),
            lifetime,
        })
    };
    Some([with(TICKET_LIFETIME), with(0)])
});
static SESSIONS: LazyLock<Arc<dyn StoresServerSessions>> =
    LazyLock::new(|| rustls::server::ServerSessionMemoryCache::new(256));

/// The certificate chosen for one connection.
#[derive(Debug)]
struct Chosen(Option<Arc<CertifiedKey>>);

#[expect(clippy::missing_trait_methods, reason = "defaults are rustls's")]
impl ResolvesServerCert for Chosen {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}

/// `tls.RequestClientCert`: ask for a certificate naming these CAs, accept
/// none or any, but still check the handshake signature.
#[derive(Debug)]
struct RequestClientCert {
    hints: Vec<DistinguishedName>,
    algorithms: WebPkiSupportedAlgorithms,
    /// Go requests no PKCS#1 v1.5 signatures in TLS 1.3.
    tls13: bool,
}

#[expect(clippy::missing_trait_methods, reason = "defaults are rustls's")]
impl ClientCertVerifier for RequestClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let supported = self.algorithms.supported_schemes();
        GO_SIGNATURE_SCHEMES
            .into_iter()
            .filter(|scheme| supported.contains(scheme))
            .filter(|scheme| {
                !self.tls13
                    || !matches!(
                        scheme,
                        SignatureScheme::RSA_PKCS1_SHA256
                            | SignatureScheme::RSA_PKCS1_SHA384
                            | SignatureScheme::RSA_PKCS1_SHA512
                    )
            })
            .collect()
    }
}

/// The client CA subjects Go sends in the `CertificateRequest`
/// (`x509.CertPool.Subjects`).
fn subjects(cas: &[CertificateDer<'static>]) -> Vec<DistinguishedName> {
    let mut store = RootCertStore::empty();
    store.add_parsable_certificates(cas.iter().cloned());
    store.subjects()
}

/// Whether rustls will negotiate TLS 1.3 with this client: it does whenever
/// the client offers it, and TLS 1.3 clients offer TLS 1.3 suites.
fn offers_tls13(client_hello: &ClientHello<'_>) -> bool {
    client_hello.cipher_suites().iter().any(|suite| {
        matches!(
            suite,
            CipherSuite::TLS13_AES_128_GCM_SHA256
                | CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    })
}

/// `GetTLSConfig` with the chosen certificate and client CAs.
fn go_config(
    certificate: Option<Arc<CertifiedKey>>,
    client_cas: Option<&[CertificateDer<'static>]>,
    tls13: bool,
) -> Option<Arc<ServerConfig>> {
    let provider = Arc::clone(&GO_PROVIDER);
    let algorithms = provider.signature_verification_algorithms;
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .inspect_err(|err| warn!(?err, "invalid TLS configuration"))
        .ok()?;
    let builder = match client_cas {
        Some(cas) => builder.with_client_cert_verifier(Arc::new(RequestClientCert {
            hints: subjects(cas),
            algorithms,
            tls13,
        })),
        None => builder.with_no_client_auth(),
    };
    let certificate = certificate.map(|key| go_signing(&key));
    let mut config = builder.with_cert_resolver(Arc::new(Chosen(certificate)));
    config.ignore_client_order = true;
    // Go sends one TLS 1.3 ticket.
    config.send_tls13_tickets = 1;
    config.session_storage = Arc::clone(&SESSIONS);
    if let Some([tls13_ticketer, tls12_ticketer]) = TICKETERS.as_ref() {
        config.ticketer = Arc::clone(if tls13 {
            tls13_ticketer
        } else {
            tls12_ticketer
        });
    }
    Some(Arc::new(config))
}

impl Server {
    /// `WebServer.GetCertificate`'s `GetConfigForClient`.
    fn tls_config_for(&self, client_hello: &ClientHello<'_>) -> Option<Arc<ServerConfig>> {
        let server_name = client_hello.server_name().unwrap_or_default();
        if !server_name.is_empty()
            && let Some(proxy_outpost) = self.proxy_outpost.load_full()
            && let Some(cert) = proxy_outpost.resolve_cert(client_hello)
        {
            return go_config(Some(cert), None, offers_tls13(client_hello));
        }
        let selection = self.brand_tls.load().select(server_name);
        let certificate = match selection.web {
            WebCertificate::Fallback => Some(Arc::clone(&self.fallback_cert)),
            WebCertificate::Keypair(key) => Some(key),
            WebCertificate::NoPrivateKey => None,
        };
        trace!("using brand web Certificate");
        go_config(
            certificate,
            selection.client_cas.as_deref(),
            offers_tls13(client_hello),
        )
    }
}

pub(super) fn config_for_hello(server: Arc<Server>) -> ConfigForHello {
    Arc::new(move |client_hello| server.tls_config_for(client_hello))
}

/// `Watcher.Start`: check right away once Django is up, then every three
/// minutes. A failed check keeps the previous brands and certificates.
pub(super) async fn watch_tls_config(arbiter: Arbiter, server: Arc<Server>) -> Result<()> {
    let mut events_rx = arbiter.events_subscribe();

    info!("waiting for gunicorn to be ready before starting tls watcher");
    loop {
        tokio::select! {
            event = events_rx.recv() => {
                if event == Ok(Event::GunicornIsReady) {
                    break;
                }
            },
            () = arbiter.shutdown() => {
                warn!("we were told to shutdown before starting the tls watcher");
                return Ok(());
            },
        }
    }

    info!("Starting Brand TLS Checker");
    loop {
        let current = server.brand_tls.load_full();
        match current.check().await {
            Ok(next) => {
                server.brand_tls.store(Arc::new(next));
                debug!("reloaded brand certificates");
            }
            Err(err) => warn!(?err, "failed to get brands"),
        }

        tokio::select! {
            () = tokio::time::sleep(Duration::from_mins(3)) => {},
            () = arbiter.shutdown() => return Ok(()),
        }
    }
}

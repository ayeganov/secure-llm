//! TLS interception for the MITM proxy.
//!
//! This module provides:
//! - Certificate caching to avoid regeneration overhead
//! - Dynamic certificate resolution using SNI
//! - TLS acceptor for client connections (proxy as server)
//! - TLS connector for upstream connections (proxy as client)
//!
//! # Critical ALPN Note
//!
//! We **must** force HTTP/1.1 via ALPN. If we allow HTTP/2 negotiation,
//! modern clients (curl, browsers, SDKs) will upgrade to H2 after the TLS
//! handshake. Our simple bidirectional copy loop doesn't understand H2
//! framing (multiplexed streams, binary protocol), causing connection
//! failures or data corruption.
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::proxy::tls::{CertificateCache, create_tls_acceptor, create_tls_connector};
//! use secure_llm::sandbox::ca::EphemeralCa;
//! use std::sync::Arc;
//!
//! let ca = Arc::new(EphemeralCa::generate()?);
//! let cache = Arc::new(CertificateCache::new(ca));
//!
//! // For accepting client connections
//! let acceptor = create_tls_acceptor(cache.clone(), Some("example.com".into()))?;
//!
//! // For connecting to upstream servers
//! let connector = create_tls_connector()?;
//! ```

use super::error::ProxyError;
use crate::sandbox::ca::EphemeralCa;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, trace};

/// Certificate cache for TLS interception.
///
/// Caches generated certificates to avoid the overhead of regenerating
/// certificates for every connection. Certificates are cached by domain name.
pub struct CertificateCache {
    /// Cache of domain -> certified key.
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Reference to the ephemeral CA for generating new certificates.
    ca: Arc<EphemeralCa>,
}

impl CertificateCache {
    /// Create a new certificate cache with the given CA.
    pub fn new(ca: Arc<EphemeralCa>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ca,
        }
    }

    /// Get or generate a certificate for the given domain.
    ///
    /// If a certificate exists in the cache, returns it.
    /// Otherwise, generates a new one, caches it, and returns it.
    pub fn get_or_generate(&self, domain: &str) -> Result<Arc<CertifiedKey>, ProxyError> {
        let domain_lower = domain.to_lowercase();

        // Check cache first (read lock)
        {
            let cache = self.cache.read().unwrap();
            if let Some(key) = cache.get(&domain_lower) {
                trace!("Certificate cache hit for {}", domain);
                return Ok(key.clone());
            }
        }

        debug!("Generating certificate for {}", domain);

        // Generate new certificate using the CA
        let domain_cert = self.ca.generate_cert(domain)?;

        // Parse the certificate chain from PEM
        let cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut domain_cert.cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ProxyError::Tls(format!("Failed to parse certificate PEM: {}", e)))?;

        if cert_chain.is_empty() {
            return Err(ProxyError::Tls("No certificates found in PEM".into()));
        }

        // Parse the private key from PEM
        let private_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut domain_cert.key_pem.as_bytes())
                .map_err(|e| ProxyError::Tls(format!("Failed to parse private key PEM: {}", e)))?
                .ok_or_else(|| ProxyError::Tls("No private key found in PEM".into()))?;

        // Create the signing key
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
            .map_err(|e| ProxyError::Tls(format!("Failed to create signing key: {}", e)))?;

        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        // Cache it (write lock)
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(domain_lower, certified_key.clone());
        }

        Ok(certified_key)
    }

    /// Clear the certificate cache.
    ///
    /// Useful for testing or when the CA is rotated.
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
        debug!("Certificate cache cleared");
    }

    /// Get the number of cached certificates.
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().unwrap().is_empty()
    }
}

/// Certificate resolver that generates certificates on-demand.
///
/// This implements rustls's `ResolvesServerCert` trait to dynamically
/// generate certificates based on the SNI (Server Name Indication)
/// in the TLS ClientHello.
pub struct DynamicCertResolver {
    /// Certificate cache for on-demand generation.
    cache: Arc<CertificateCache>,
    /// Domain hint (from CONNECT request) for SNI-less clients.
    domain_hint: Option<String>,
}

impl DynamicCertResolver {
    /// Create a new resolver without a domain hint.
    ///
    /// The resolver will use SNI from the ClientHello.
    pub fn new(cache: Arc<CertificateCache>) -> Self {
        Self {
            cache,
            domain_hint: None,
        }
    }

    /// Create a resolver with a domain hint.
    ///
    /// The hint is used when the client doesn't send SNI.
    /// This can happen with some older clients or when the client
    /// connects directly by IP address.
    pub fn with_domain_hint(cache: Arc<CertificateCache>, domain: String) -> Self {
        Self {
            cache,
            domain_hint: Some(domain),
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Get domain from SNI or fall back to hint
        let domain = client_hello
            .server_name()
            .map(|s| s.to_string())
            .or_else(|| self.domain_hint.clone())?;

        trace!("Resolving certificate for: {}", domain);

        match self.cache.get_or_generate(&domain) {
            Ok(key) => Some(key),
            Err(e) => {
                error!("Failed to generate certificate for {}: {}", domain, e);
                None
            }
        }
    }
}

// Required for Arc<DynamicCertResolver> to implement ResolvesServerCert
impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("domain_hint", &self.domain_hint)
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

/// Create a TLS acceptor for client connections.
///
/// This is used to accept TLS connections from clients inside the sandbox.
/// The proxy acts as the server, presenting dynamically generated certificates.
///
/// # Arguments
///
/// * `cert_cache` - Certificate cache for on-demand generation.
/// * `domain_hint` - Optional domain hint for SNI-less clients.
///
/// # Critical ALPN Note
///
/// This function forces HTTP/1.1 via ALPN to prevent HTTP/2 negotiation.
/// Without this, clients supporting H2 will upgrade after TLS handshake,
/// and our proxy's bidirectional copy won't understand H2 framing.
pub fn create_tls_acceptor(
    cert_cache: Arc<CertificateCache>,
    domain_hint: Option<String>,
) -> Result<TlsAcceptor, ProxyError> {
    let resolver: Arc<dyn ResolvesServerCert> = if let Some(domain) = domain_hint {
        Arc::new(DynamicCertResolver::with_domain_hint(cert_cache, domain))
    } else {
        Arc::new(DynamicCertResolver::new(cert_cache))
    };

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // CRITICAL: Force HTTP/1.1 to prevent HTTP/2 negotiation.
    // Without this, clients that support H2 will upgrade after TLS handshake,
    // and our proxy's bidirectional copy won't understand H2 framing.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Create a TLS connector for upstream connections.
///
/// This is used to connect to upstream servers. The proxy acts as a client,
/// verifying the upstream server's certificate against system root CAs.
pub fn create_tls_connector() -> Result<TlsConnector, ProxyError> {
    // Load system root certificates
    let mut root_store = rustls::RootCertStore::empty();

    let native_certs = rustls_native_certs::load_native_certs();

    // Log any errors but continue with successfully loaded certs
    for err in native_certs.errors {
        debug!("Warning loading native cert: {}", err);
    }

    for cert in native_certs.certs {
        if let Err(e) = root_store.add(cert) {
            debug!("Warning adding cert to store: {}", e);
        }
    }

    if root_store.is_empty() {
        return Err(ProxyError::Tls(
            "No system root certificates found".into(),
        ));
    }

    debug!("Loaded {} root certificates", root_store.len());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Convert a domain string to a ServerName for TLS connection.
pub fn domain_to_server_name(domain: &str) -> Result<ServerName<'static>, ProxyError> {
    ServerName::try_from(domain.to_string())
        .map_err(|_| ProxyError::Tls(format!("Invalid server name: {}", domain)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_cache_creation() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = CertificateCache::new(ca);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_certificate_generation_and_caching() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = CertificateCache::new(ca);

        // First call should generate
        let key1 = cache.get_or_generate("example.com").unwrap();
        assert_eq!(cache.len(), 1);

        // Second call should return cached
        let key2 = cache.get_or_generate("example.com").unwrap();
        assert_eq!(cache.len(), 1);

        // Should be the same Arc (same pointer)
        assert!(Arc::ptr_eq(&key1, &key2));
    }

    #[test]
    fn test_certificate_cache_case_insensitive() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = CertificateCache::new(ca);

        // Generate for lowercase
        let _key1 = cache.get_or_generate("example.com").unwrap();
        assert_eq!(cache.len(), 1);

        // Should hit cache for uppercase
        let _key2 = cache.get_or_generate("EXAMPLE.COM").unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_certificate_cache_clear() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = CertificateCache::new(ca);

        cache.get_or_generate("example.com").unwrap();
        cache.get_or_generate("test.com").unwrap();
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_dynamic_cert_resolver_creation() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertificateCache::new(ca));

        let _resolver = DynamicCertResolver::new(cache.clone());
        let _resolver_with_hint =
            DynamicCertResolver::with_domain_hint(cache, "example.com".into());
    }

    #[test]
    fn test_tls_acceptor_creation() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let cache = Arc::new(CertificateCache::new(ca));

        let acceptor = create_tls_acceptor(cache, Some("example.com".into()));
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_tls_connector_creation() {
        // This test may fail on systems without root certificates
        // but that's a valid failure case
        let result = create_tls_connector();
        // Just check it doesn't panic - may fail on minimal systems
        let _ = result;
    }

    #[test]
    fn test_domain_to_server_name() {
        assert!(domain_to_server_name("example.com").is_ok());
        assert!(domain_to_server_name("api.github.com").is_ok());
        // Invalid names (empty is invalid)
        assert!(domain_to_server_name("").is_err());
    }
}

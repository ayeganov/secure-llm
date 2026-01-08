//! Ephemeral CA certificate management for TLS interception.
//!
//! This module generates ephemeral Root CA certificates that are:
//! - Created fresh for each session (no persistent CA = no long-term compromise)
//! - Injected into the sandbox's trust store
//! - Used to dynamically generate per-site certificates for the MITM proxy
//! - Automatically deleted on exit
//!
//! # Security Model
//!
//! - CA private key is stored with 0600 permissions
//! - CA directory has 0700 permissions
//! - All CA material is deleted when the `EphemeralCa` is dropped
//! - Certificates have short validity (24 hours)
//!
//! # Combined CA Bundle
//!
//! **Critical**: The sandbox needs to trust both:
//! 1. Our ephemeral CA (for proxied HTTPS traffic)
//! 2. The host's system CAs (for signature verification, non-proxied traffic)
//!
//! Use `create_combined_bundle()` to create a bundle containing both.
//! Do NOT just mount the ephemeral CA alone as the system trust store.
//!
//! # Example
//!
//! ```ignore
//! use secure_llm::sandbox::ca::EphemeralCa;
//!
//! let ca = EphemeralCa::generate()?;
//!
//! // Create combined bundle for bind-mounting
//! let bundle = ca.create_combined_bundle(Path::new("/etc/ssl/certs/ca-certificates.crt"))?;
//!
//! // Generate a certificate for a domain (used by MITM proxy)
//! let domain_cert = ca.generate_cert("api.example.com")?;
//! ```

use super::error::CaError;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, Issuer,
    KeyUsagePurpose, SanType,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, warn};

/// Short validity period for certificates (24 hours).
const CERT_VALIDITY_DAYS: i64 = 1;

/// Ephemeral CA for TLS interception.
///
/// The CA is generated fresh for each session and automatically
/// cleaned up when dropped.
pub struct EphemeralCa {
    /// Path to temp directory containing CA files.
    temp_dir: PathBuf,
    /// Path to CA certificate (PEM format).
    cert_path: PathBuf,
    /// Path to CA private key (PEM format).
    key_path: PathBuf,
    /// The CA key pair (for signing domain certificates).
    ca_key_pair: rcgen::KeyPair,
    /// The CA certificate parameters (for creating Issuer).
    ca_params: CertificateParams,
    /// PEM-encoded CA certificate.
    ca_cert_pem: String,
    /// Whether to delete files on drop.
    cleanup_on_drop: bool,
}

/// Certificate generated for a specific domain.
pub struct DomainCertificate {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

impl EphemeralCa {
    /// Generate a new ephemeral CA.
    ///
    /// Creates a temporary directory with restrictive permissions
    /// containing the CA certificate and private key.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Temporary directory cannot be created
    /// - Key generation fails
    /// - Certificate generation fails
    /// - File write fails
    pub fn generate() -> Result<Self, CaError> {
        info!("Generating ephemeral CA certificate");

        // Create secure temp directory
        let temp_dir = tempfile::Builder::new()
            .prefix("secure-llm-ca-")
            .tempdir()
            .map_err(CaError::TempDir)?;

        // Set restrictive permissions on directory (0700)
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(CaError::Permissions)?;

        // Generate CA key pair using ECDSA P-384
        let ca_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| CaError::KeyGeneration(e.to_string()))?;

        // Build CA certificate parameters
        let mut ca_params = CertificateParams::default();

        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("secure-llm Ephemeral CA".to_string()),
        );
        dn.push(
            DnType::OrganizationName,
            DnValue::Utf8String("secure-llm".to_string()),
        );
        ca_params.distinguished_name = dn;

        // CA constraints
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Short validity (24 hours) - using time crate as rcgen expects
        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now + Duration::days(CERT_VALIDITY_DAYS);

        // Generate the CA certificate (self-signed)
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key_pair)
            .map_err(|e| CaError::CertGeneration(e.to_string()))?;

        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key_pair.serialize_pem();

        // Write certificate file
        let cert_path = temp_dir.path().join("ca.crt");
        fs::write(&cert_path, &ca_cert_pem).map_err(CaError::WriteFile)?;

        // Write key file with extra restricted permissions (0600)
        let key_path = temp_dir.path().join("ca.key");
        write_restricted_file(&key_path, &ca_key_pem)?;

        // Keep temp_dir ownership to prevent early deletion
        // TempDir::keep() returns PathBuf directly
        let temp_path = temp_dir.keep();

        debug!(
            "Ephemeral CA generated: cert={:?}, key={:?}",
            cert_path, key_path
        );

        Ok(Self {
            temp_dir: temp_path,
            cert_path,
            key_path,
            ca_key_pair,
            ca_params,
            ca_cert_pem,
            cleanup_on_drop: true,
        })
    }

    /// Get path to CA certificate (for trust store injection).
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Get path to CA private key.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Get CA certificate as PEM string.
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Create a combined CA bundle (Host system CAs + our Ephemeral CA).
    ///
    /// **Critical**: Do NOT just mount our ephemeral CA as the system trust store.
    /// That would break any tool that verifies signed artifacts not going through
    /// the proxy (e.g., signature verification on binaries, local passthrough).
    ///
    /// This method:
    /// 1. Reads the host's CA bundle (gracefully handles missing)
    /// 2. Appends our ephemeral CA to the end
    /// 3. Writes the combined bundle to a temp file
    /// 4. Returns the path for bind-mounting
    ///
    /// # Arguments
    ///
    /// * `host_bundle_path` - Path to the host's CA bundle (e.g., `/etc/ssl/certs/ca-certificates.crt`)
    ///
    /// # Errors
    ///
    /// Returns error if reading or writing fails.
    pub fn create_combined_bundle(&self, host_bundle_path: &Path) -> Result<PathBuf, CaError> {
        debug!(
            "Creating combined CA bundle from {:?} + ephemeral CA",
            host_bundle_path
        );

        let mut bundle_content = String::new();

        // Try to read host bundle (gracefully handle missing, e.g., minimal containers)
        if host_bundle_path.exists() {
            bundle_content =
                fs::read_to_string(host_bundle_path).map_err(CaError::ReadFile)?;
            // Ensure there's a newline before appending
            if !bundle_content.ends_with('\n') {
                bundle_content.push('\n');
            }
            debug!("Read {} bytes from host CA bundle", bundle_content.len());
        } else {
            warn!(
                "Host CA bundle not found at {:?}, using ephemeral CA only",
                host_bundle_path
            );
        }

        // Append our ephemeral CA
        bundle_content.push_str(&self.ca_cert_pem);

        // Write to a new temp file in our secure directory
        let bundle_path = self.temp_dir.join("combined-ca-bundle.crt");
        fs::write(&bundle_path, &bundle_content).map_err(CaError::WriteFile)?;

        debug!(
            "Combined CA bundle written to {:?} ({} bytes)",
            bundle_path,
            bundle_content.len()
        );

        Ok(bundle_path)
    }

    /// Generate a certificate for a domain, signed by this CA.
    ///
    /// Used by the MITM proxy (Phase 3) to present valid certificates.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to generate a certificate for.
    ///
    /// # Errors
    ///
    /// Returns error if certificate generation fails.
    pub fn generate_cert(&self, domain: &str) -> Result<DomainCertificate, CaError> {
        self.generate_cert_multi(&[domain])
    }

    /// Generate a certificate for multiple domains (SANs).
    ///
    /// Useful for wildcard certificates or certificates with multiple domains.
    ///
    /// # Arguments
    ///
    /// * `domains` - List of domain names to include in the certificate.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No domains specified
    /// - Key generation fails
    /// - Certificate generation fails
    pub fn generate_cert_multi(&self, domains: &[&str]) -> Result<DomainCertificate, CaError> {
        if domains.is_empty() {
            return Err(CaError::NoDomains);
        }

        debug!("Generating certificate for domains: {:?}", domains);

        // Generate key for this domain certificate
        let domain_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| CaError::KeyGeneration(e.to_string()))?;

        let mut params = CertificateParams::default();

        // Use first domain as CN
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String(domains[0].to_string()),
        );
        params.distinguished_name = dn;

        // Add all domains as Subject Alternative Names
        params.subject_alt_names = domains
            .iter()
            .map(|d| SanType::DnsName((*d).try_into().unwrap()))
            .collect();

        // Short validity (same as CA)
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(CERT_VALIDITY_DAYS);

        // Create an Issuer from our CA params and key pair
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key_pair);

        // Generate the certificate signed by our CA
        let domain_cert = params
            .signed_by(&domain_key_pair, &issuer)
            .map_err(|e| CaError::Signing(e.to_string()))?;

        Ok(DomainCertificate {
            cert_pem: domain_cert.pem(),
            key_pem: domain_key_pair.serialize_pem(),
        })
    }

    /// Disable cleanup on drop (for debugging).
    ///
    /// **Warning**: This leaves the CA key material on disk. Only use for debugging.
    pub fn persist(&mut self) {
        warn!("CA persistence enabled - key material will not be deleted on exit");
        self.cleanup_on_drop = false;
    }

    /// Get the temp directory path (for debugging).
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Manually clean up CA files.
    fn cleanup(&self) {
        debug!("Cleaning up ephemeral CA at {:?}", self.temp_dir);
        if let Err(e) = fs::remove_dir_all(&self.temp_dir) {
            warn!("Failed to clean up CA temp directory: {}", e);
        }
    }
}

impl Drop for EphemeralCa {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            self.cleanup();
        }
    }
}

/// Write a file with restricted permissions (0600).
fn write_restricted_file(path: &Path, content: &str) -> Result<(), CaError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(CaError::WriteFile)?;

    file.write_all(content.as_bytes())
        .map_err(CaError::WriteFile)?;

    Ok(())
}

/// Standard host CA bundle locations to try.
pub const HOST_CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // Alpine/macOS
];

/// Find the first existing host CA bundle.
pub fn find_host_ca_bundle() -> Option<&'static Path> {
    HOST_CA_BUNDLES
        .iter()
        .map(|p| Path::new(*p))
        .find(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = EphemeralCa::generate().unwrap();
        assert!(ca.cert_path().exists());
        assert!(ca.key_path().exists());
    }

    #[test]
    fn test_cert_pem_content() {
        let ca = EphemeralCa::generate().unwrap();
        let pem = ca.cert_pem();
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_domain_cert_generation() {
        let ca = EphemeralCa::generate().unwrap();
        let cert = ca.generate_cert("example.com").unwrap();

        assert!(cert.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_multi_domain_cert() {
        let ca = EphemeralCa::generate().unwrap();
        let cert = ca
            .generate_cert_multi(&["example.com", "www.example.com", "api.example.com"])
            .unwrap();

        assert!(cert.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_no_domains_error() {
        let ca = EphemeralCa::generate().unwrap();
        let result = ca.generate_cert_multi(&[]);
        assert!(matches!(result, Err(CaError::NoDomains)));
    }

    #[test]
    fn test_cleanup_on_drop() {
        let path;
        {
            let ca = EphemeralCa::generate().unwrap();
            path = ca.temp_dir.clone();
            assert!(path.exists());
        }
        // After drop, directory should be deleted
        assert!(!path.exists());
    }

    #[test]
    fn test_persist_prevents_cleanup() {
        let path;
        {
            let mut ca = EphemeralCa::generate().unwrap();
            ca.persist();
            path = ca.temp_dir.clone();
            assert!(path.exists());
        }
        // After drop with persist(), directory should still exist
        assert!(path.exists());
        // Manual cleanup
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn test_restricted_permissions() {
        let ca = EphemeralCa::generate().unwrap();

        // Key file should have 0600 permissions
        let key_meta = fs::metadata(ca.key_path()).unwrap();
        let key_mode = key_meta.permissions().mode();
        assert_eq!(
            key_mode & 0o777,
            0o600,
            "Key file should have 0600 permissions"
        );

        // Temp directory should have 0700 permissions
        let dir_meta = fs::metadata(&ca.temp_dir).unwrap();
        let dir_mode = dir_meta.permissions().mode();
        assert_eq!(
            dir_mode & 0o777,
            0o700,
            "Temp directory should have 0700 permissions"
        );
    }

    #[test]
    fn test_combined_bundle_includes_host_cas() {
        let ca = EphemeralCa::generate().unwrap();

        // Create a fake host bundle
        let temp_dir = tempfile::tempdir().unwrap();
        let host_bundle = temp_dir.path().join("ca-certificates.crt");
        let host_ca_content =
            "-----BEGIN CERTIFICATE-----\nHOSTCA\n-----END CERTIFICATE-----\n";
        fs::write(&host_bundle, host_ca_content).unwrap();

        // Create combined bundle
        let combined_path = ca.create_combined_bundle(&host_bundle).unwrap();
        let combined_content = fs::read_to_string(&combined_path).unwrap();

        // Should contain both host CAs and our ephemeral CA
        assert!(combined_content.contains("HOSTCA"));
        // Check that our CA cert was appended (PEM content is base64, not plaintext)
        assert!(combined_content.contains(ca.cert_pem()));
    }

    #[test]
    fn test_combined_bundle_handles_missing_host_bundle() {
        let ca = EphemeralCa::generate().unwrap();
        let nonexistent = Path::new("/nonexistent/ca-bundle.crt");

        // Should still succeed, just containing our CA
        let combined_path = ca.create_combined_bundle(nonexistent).unwrap();
        let combined_content = fs::read_to_string(&combined_path).unwrap();

        assert!(combined_content.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_find_host_ca_bundle() {
        // This test depends on the system, so we just check it doesn't panic
        let _ = find_host_ca_bundle();
    }
}

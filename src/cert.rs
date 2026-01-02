// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::ca::Ca;
use crate::config::Paths;
use crate::error::{Error, Result};
use crate::fs::{atomic_write, atomic_write_secret, is_reserved_name};
use once_cell::sync::Lazy;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    KeyPair, KeyUsagePurpose, SanType,
};
use regex::Regex;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

/// Pre-compiled email regex pattern for validation
/// - No consecutive dots in local part
/// - No leading/trailing dots in local part
/// - No leading/trailing hyphens in domain labels
/// - Requires at least one dot in domain (TLD)
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$")
        .expect("invalid email regex")
});

/// A generated certificate with its private key.
pub struct Cert {
    /// The certificate in PEM format.
    pub pem: String,
    /// The private key in PEM format.
    pub key_pem: String,
    /// The domains or identifiers covered by this certificate.
    pub domains: Vec<String>,
}

/// Result of certificate generation, including optional warnings.
pub struct CertGenerateResult {
    /// The generated certificate.
    pub cert: Cert,
    /// Warning message if the certificate outlives the CA or has other issues.
    pub warning: Option<String>,
}

/// Result of signing a Certificate Signing Request (CSR).
#[derive(Debug)]
pub struct CsrSignResult {
    /// The signed certificate in PEM format.
    pub cert_pem: String,
    /// Warning message if the certificate outlives the CA or has other issues.
    pub warning: Option<String>,
}

/// Maximum certificate validity period (10 years).
pub const MAX_CERT_DAYS: u32 = 3650;

/// Check if a certificate with the given validity will outlive the CA.
/// Returns a warning message if so, None otherwise.
fn check_ca_expiry_warning(ca: &Ca, days: u32) -> Option<String> {
    ca.days_remaining().ok().and_then(|ca_days_remaining| {
        if (days as i64) > ca_days_remaining {
            Some(format!(
                "Certificate validity ({} days) exceeds CA's remaining validity ({} days). \
                 The certificate will become invalid when the CA expires.",
                days, ca_days_remaining
            ))
        } else {
            None
        }
    })
}

/// Validate that the validity period is within allowed bounds.
///
/// # Errors
/// Returns an error if `days` is 0 or exceeds [`MAX_CERT_DAYS`].
pub fn validate_days(days: u32) -> Result<()> {
    if days == 0 {
        return Err(Error::InvalidDays("days cannot be 0".into()));
    }
    if days > MAX_CERT_DAYS {
        return Err(Error::InvalidDays(format!(
            "days cannot exceed {} (10 years)",
            MAX_CERT_DAYS
        )));
    }
    Ok(())
}

/// Default domain names included in localhost certificates.
pub const LOCALHOST_DOMAINS: &[&str] = &["localhost", "*.localhost"];

/// Default IP addresses included in localhost certificates.
pub const LOCALHOST_IPS: &[&str] = &["127.0.0.1", "::1"];

/// Certificate purpose for generation
#[derive(Debug, Clone, Copy)]
enum CertPurpose {
    Server,
    Client,
    Smime,
}

/// Internal parameters for unified certificate generation
struct CertGenParams<'a> {
    purpose: CertPurpose,
    domains: &'a [String],
    emails: &'a [String],
    days: u32,
}

/// Unified certificate generation logic
fn generate_with_params(ca: &Ca, params: CertGenParams) -> Result<CertGenerateResult> {
    validate_days(params.days)?;

    // Validate based on purpose and collect warnings
    let mut all_warnings = Vec::new();

    match params.purpose {
        CertPurpose::Smime => {
            validate_emails(params.emails)?;
            if !params.domains.is_empty() {
                let domain_warnings = validate_domains(params.domains)?;
                all_warnings.extend(domain_warnings);
            }
            if params.emails.is_empty() {
                return Err(Error::InvalidEmail {
                    email: String::new(),
                    reason: "At least one email address is required for S/MIME certificates".into(),
                });
            }
        }
        _ => {
            let domain_warnings = validate_domains(params.domains)?;
            all_warnings.extend(domain_warnings);
        }
    }

    // Combine CA expiry warning with domain warnings
    let mut warning = check_ca_expiry_warning(ca, params.days);
    if !all_warnings.is_empty() {
        let domain_warning = all_warnings.join("; ");
        warning = match warning {
            Some(w) => Some(format!("{}; {}", w, domain_warning)),
            None => Some(domain_warning),
        };
    }

    let mut cert_params = CertificateParams::default();

    // Set common name based on purpose
    match params.purpose {
        CertPurpose::Smime => {
            if let Some(first_email) = params.emails.first() {
                cert_params
                    .distinguished_name
                    .push(DnType::CommonName, first_email);
            }
        }
        _ => {
            if let Some(first) = params.domains.first() {
                cert_params
                    .distinguished_name
                    .push(DnType::CommonName, first);
            }
        }
    }

    // Add email SANs for S/MIME
    if matches!(params.purpose, CertPurpose::Smime) {
        for email in params.emails {
            cert_params.subject_alt_names.push(SanType::Rfc822Name(
                email.clone().try_into().map_err(|_| Error::InvalidEmail {
                    email: email.clone(),
                    reason: "Invalid email format for SAN".into(),
                })?,
            ));
        }
    }

    // Add domain/IP SANs
    for domain in params.domains {
        let ip_candidate = domain.split('%').next().unwrap_or(domain);
        if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
            cert_params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            cert_params.subject_alt_names.push(SanType::DnsName(
                domain
                    .clone()
                    .try_into()
                    .map_err(|_| Error::InvalidDomain {
                        domain: domain.clone(),
                        reason: "Invalid DNS name".into(),
                    })?,
            ));
        }
    }

    // Set key usages based on purpose
    cert_params.key_usages = match params.purpose {
        CertPurpose::Smime => vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::ContentCommitment,
        ],
        _ => vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ],
    };

    // Set EKU based on purpose
    cert_params.extended_key_usages = match params.purpose {
        CertPurpose::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
        CertPurpose::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
        CertPurpose::Smime => vec![ExtendedKeyUsagePurpose::EmailProtection],
    };

    // Set validity period
    let now = time::OffsetDateTime::now_utc();
    cert_params.not_before = now;
    cert_params.not_after = now + time::Duration::days(params.days as i64);

    // Generate key pair and sign
    let key_pair = KeyPair::generate()?;
    let issuer = ca.issuer()?;
    let cert = cert_params.signed_by(&key_pair, &issuer)?;

    // Build result - for S/MIME, include both emails and domains
    let all_names = if matches!(params.purpose, CertPurpose::Smime) {
        let mut names = params.emails.to_vec();
        names.extend(params.domains.iter().cloned());
        names
    } else {
        params.domains.to_vec()
    };

    Ok(CertGenerateResult {
        cert: Cert {
            pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            domains: all_names,
        },
        warning,
    })
}

/// Validate email addresses for S/MIME certificate generation.
///
/// Checks that each email matches RFC 5321 format requirements.
pub fn validate_emails(emails: &[String]) -> Result<()> {
    if emails.is_empty() {
        return Ok(());
    }

    for email in emails {
        if !EMAIL_REGEX.is_match(email) {
            return Err(Error::InvalidEmail {
                email: email.clone(),
                reason: "Invalid email format".into(),
            });
        }
    }

    Ok(())
}

impl Cert {
    /// Generate server certificate for the given domains.
    pub fn generate(ca: &Ca, domains: &[String], days: u32) -> Result<CertGenerateResult> {
        generate_with_params(
            ca,
            CertGenParams {
                purpose: CertPurpose::Server,
                domains,
                emails: &[],
                days,
            },
        )
    }

    /// Generate localhost certificate (includes 127.0.0.1 and ::1).
    pub fn generate_localhost(ca: &Ca, days: u32) -> Result<CertGenerateResult> {
        let mut domains: Vec<String> = LOCALHOST_DOMAINS.iter().map(|s| s.to_string()).collect();
        domains.extend(LOCALHOST_IPS.iter().map(|s| s.to_string()));
        Self::generate(ca, &domains, days)
    }

    /// Generate client certificate for mTLS.
    pub fn generate_client(ca: &Ca, domains: &[String], days: u32) -> Result<CertGenerateResult> {
        generate_with_params(
            ca,
            CertGenParams {
                purpose: CertPurpose::Client,
                domains,
                emails: &[],
                days,
            },
        )
    }

    /// Generate S/MIME certificate for email encryption.
    pub fn generate_smime(
        ca: &Ca,
        emails: &[String],
        domains: &[String],
        days: u32,
    ) -> Result<CertGenerateResult> {
        generate_with_params(
            ca,
            CertGenParams {
                purpose: CertPurpose::Smime,
                domains,
                emails,
                days,
            },
        )
    }

    /// Export cert and key as PKCS12 (.p12) file.
    pub fn export_pkcs12(&self, path: &Path, password: &str) -> Result<()> {
        use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKeyChain};

        // Parse the certificate PEM to DER
        let cert_der = pem::parse(&self.pem)
            .map_err(|e| Error::Pkcs12Export(format!("Failed to parse certificate PEM: {}", e)))?
            .into_contents();

        // Parse the private key PEM to DER
        let key_der = pem::parse(&self.key_pem)
            .map_err(|e| Error::Pkcs12Export(format!("Failed to parse private key PEM: {}", e)))?
            .into_contents();

        // Create Certificate from DER
        let cert = Certificate::from_der(&cert_der)
            .map_err(|e| Error::Pkcs12Export(format!("Failed to parse certificate DER: {}", e)))?;

        // Create a new keystore
        let mut keystore = KeyStore::new();

        // Create a private key chain with the certificate
        // local_key_id can be empty or a unique identifier
        let key_chain = PrivateKeyChain::new(&key_der, [], vec![cert]);
        keystore.add_entry("devssl", KeyStoreEntry::PrivateKeyChain(key_chain));

        // Export to PKCS12 format using the writer
        let p12_data = keystore
            .writer(password)
            .write()
            .map_err(|e| Error::Pkcs12Export(format!("Failed to create PKCS12: {}", e)))?;

        // Write to file
        fs::write(path, p12_data).map_err(|e| Error::WriteFile {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Sign a CSR file with the CA.
    pub fn sign_csr(ca: &Ca, csr_path: &Path, days: u32) -> Result<CsrSignResult> {
        validate_days(days)?;

        // Read CSR file
        let csr_pem = fs::read_to_string(csr_path).map_err(|e| Error::ReadFile {
            path: csr_path.to_path_buf(),
            source: e,
        })?;

        let csr_params = CertificateSigningRequestParams::from_pem(&csr_pem)
            .map_err(|e| Error::CsrParse(format!("Failed to parse CSR: {}", e)))?;

        // Extract domains from the CSR
        let mut domains: Vec<String> = Vec::new();

        // Extract Common Name from distinguished_name
        if let Some(cn) = csr_params
            .params
            .distinguished_name
            .get(&DnType::CommonName)
        {
            let cn_str = dn_value_to_string(cn);
            domains.push(cn_str);
        }

        // Extract DNS names, IP addresses, and emails from Subject Alternative Names
        let mut emails: Vec<String> = Vec::new();
        for san in &csr_params.params.subject_alt_names {
            match san {
                SanType::DnsName(name) => {
                    domains.push(name.to_string());
                }
                SanType::IpAddress(ip) => {
                    domains.push(ip.to_string());
                }
                SanType::Rfc822Name(email) => {
                    emails.push(email.to_string());
                }
                _ => {} // Ignore other SAN types (URIs, etc.)
            }
        }

        // CSR must have either domains or emails (for S/MIME)
        let has_domains = !domains.is_empty();
        let has_emails = !emails.is_empty();

        if !has_domains && !has_emails {
            return Err(Error::NoDomains);
        }

        // Validate domains and emails, collecting warnings
        let mut all_warnings = Vec::new();

        if has_domains {
            let domain_warnings = validate_domains(&domains)?;
            all_warnings.extend(domain_warnings);
        }

        if has_emails {
            validate_emails(&emails)?;
        }

        // Combine CA expiry warning with domain warnings
        let mut warning = check_ca_expiry_warning(ca, days);
        if !all_warnings.is_empty() {
            let domain_warning = all_warnings.join("; ");
            warning = match warning {
                Some(w) => Some(format!("{}; {}", w, domain_warning)),
                None => Some(domain_warning),
            };
        }

        // Update validity period in the params
        let now = time::OffsetDateTime::now_utc();
        let mut params = csr_params.params;
        params.not_before = now;
        params.not_after = now + time::Duration::days(days as i64);

        // Set key usages for server certificate (if not already set)
        if params.key_usages.is_empty() {
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
        }
        if params.extended_key_usages.is_empty() {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }

        // Rebuild CSR params with updated certificate params
        let csr_params = CertificateSigningRequestParams {
            params,
            public_key: csr_params.public_key,
        };

        // Sign the CSR with the CA
        let issuer = ca.issuer()?;
        let cert = csr_params.signed_by(&issuer).map_err(Error::CertGen)?;

        Ok(CsrSignResult {
            cert_pem: cert.pem(),
            warning,
        })
    }

    /// Save cert and key to disk.
    pub fn save(&self, paths: &Paths, name: &str) -> Result<()> {
        // Prevent overwriting critical CA files
        if is_reserved_name(name) {
            return Err(Error::ReservedName(name.to_string()));
        }

        let cert_path = paths.cert_path(name)?;
        let key_path = paths.key_path(name)?;

        // Use atomic writes to prevent race conditions during renewal
        atomic_write(&cert_path, self.pem.as_bytes())?;
        atomic_write_secret(&key_path, self.key_pem.as_bytes())?;
        Ok(())
    }
}

/// Maximum DNS name length per RFC 1035
const MAX_DNS_NAME_LENGTH: usize = 253;

// Only allow localhost, private IPs, and dev TLDs like .local, .test, etc.
// Returns a Vec of warnings for any issues encountered
fn validate_domains(domains: &[String]) -> Result<Vec<String>> {
    if domains.is_empty() {
        return Err(Error::NoDomains);
    }

    const ALLOWED_TLDS: &[&str] = &[
        ".test",
        ".example",
        ".invalid",
        ".localhost", // RFC 2606
        ".local",     // mDNS
        ".internal",
        ".lan",
        ".home",
        ".corp",
        ".intranet",
        ".private",
        ".devlocal",
    ];

    // Use a HashSet to detect duplicates
    let mut seen = std::collections::HashSet::new();
    let mut warnings = Vec::new();

    for domain in domains {
        let lower = domain.to_lowercase();

        // Check for duplicates
        if !seen.insert(lower.clone()) {
            warnings.push(format!("Skipping duplicate domain: {}", domain));
            continue;
        }

        // Check DNS name length (RFC 1035)
        if domain.len() > MAX_DNS_NAME_LENGTH {
            return Err(Error::InvalidDomain {
                domain: domain.clone(),
                reason: format!(
                    "DNS name exceeds maximum length of {} characters",
                    MAX_DNS_NAME_LENGTH
                ),
            });
        }

        if lower == "localhost" {
            continue;
        }

        // Strip IPv6 zone ID (e.g., "fe80::1%eth0" -> "fe80::1") before parsing
        let ip_candidate = domain.split('%').next().unwrap_or(domain);
        if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
            if !is_private_ip(&ip) {
                return Err(Error::InvalidDomain {
                    domain: domain.clone(),
                    reason: "Only private IP addresses allowed".into(),
                });
            }
            continue;
        }

        if !ALLOWED_TLDS.iter().any(|tld| lower.ends_with(tld)) {
            return Err(Error::InvalidDomain {
                domain: domain.clone(),
                reason: format!(
                    "Domain must use a safe TLD for local development. Allowed: {}",
                    ALLOWED_TLDS.join(", ")
                ),
            });
        }
    }

    Ok(warnings)
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || is_ipv6_unique_local(v6) || is_ipv6_link_local(v6),
    }
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
}

/// Convert a DnValue to a String
fn dn_value_to_string(value: &DnValue) -> String {
    match value {
        DnValue::Utf8String(s) => s.clone(),
        DnValue::PrintableString(s) => s.as_str().to_string(),
        DnValue::Ia5String(s) => s.as_str().to_string(),
        DnValue::TeletexString(s) => s.as_str().to_string(),
        // BmpString and UniversalString are UTF-16/UTF-32 encoded and rarely used for domain names
        // We extract what we can, but these are uncommon in practice
        DnValue::BmpString(s) => String::from_utf16_lossy(
            &s.as_bytes()
                .chunks(2)
                .filter_map(|chunk| {
                    if chunk.len() == 2 {
                        Some(u16::from_be_bytes([chunk[0], chunk[1]]))
                    } else {
                        None
                    }
                })
                .collect::<Vec<u16>>(),
        ),
        DnValue::UniversalString(s) => String::from_utf8_lossy(s.as_bytes()).to_string(),
        _ => String::new(), // Handle future variants
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_regex_compiles() {
        // Force EMAIL_REGEX to be initialized - will panic if regex is invalid
        let _ = &*EMAIL_REGEX;
    }

    #[test]
    fn test_validate_days_zero() {
        let result = validate_days(0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidDays(_)));
    }

    #[test]
    fn test_validate_days_max_exceeded() {
        let result = validate_days(MAX_CERT_DAYS + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_days_valid() {
        assert!(validate_days(1).is_ok());
        assert!(validate_days(30).is_ok());
        assert!(validate_days(365).is_ok());
        assert!(validate_days(MAX_CERT_DAYS).is_ok());
    }

    #[test]
    fn test_validate_domains_empty() {
        let result = validate_domains(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoDomains));
    }

    #[test]
    fn test_validate_domains_localhost() {
        assert!(validate_domains(&["localhost".into()]).is_ok());
        assert!(validate_domains(&["sub.localhost".into()]).is_ok());
        assert!(validate_domains(&["deep.sub.localhost".into()]).is_ok());
    }

    #[test]
    fn test_validate_domains_rfc2606() {
        assert!(validate_domains(&["myapp.local".into()]).is_ok());
        assert!(validate_domains(&["myapp.test".into()]).is_ok());
        assert!(validate_domains(&["myapp.example".into()]).is_ok());
        assert!(validate_domains(&["myapp.invalid".into()]).is_ok());
        assert!(validate_domains(&["myapp.internal".into()]).is_ok());
    }

    #[test]
    fn test_validate_domains_private_ips() {
        assert!(validate_domains(&["127.0.0.1".into()]).is_ok());
        assert!(validate_domains(&["192.168.1.1".into()]).is_ok());
        assert!(validate_domains(&["10.0.0.1".into()]).is_ok());
        assert!(validate_domains(&["172.16.0.1".into()]).is_ok());
        assert!(validate_domains(&["::1".into()]).is_ok());
    }

    #[test]
    fn test_validate_domains_public_ips_rejected() {
        assert!(validate_domains(&["8.8.8.8".into()]).is_err());
        assert!(validate_domains(&["1.1.1.1".into()]).is_err());
    }

    #[test]
    fn test_validate_domains_public_tlds_rejected() {
        // Any public TLD should be rejected (allowlist approach)
        assert!(validate_domains(&["example.com".into()]).is_err());
        assert!(validate_domains(&["example.org".into()]).is_err());
        assert!(validate_domains(&["example.net".into()]).is_err());
        assert!(validate_domains(&["example.io".into()]).is_err());
        assert!(validate_domains(&["example.xyz".into()]).is_err());
        assert!(validate_domains(&["example.club".into()]).is_err());
    }

    #[test]
    fn test_validate_domains_unknown_tlds_rejected() {
        // Unknown TLDs should also be rejected
        assert!(validate_domains(&["evil.xyz".into()]).is_err());
        assert!(validate_domains(&["phishing.tk".into()]).is_err());
        assert!(validate_domains(&["malware.ninja".into()]).is_err());
    }

    #[test]
    fn test_validate_domains_additional_allowed() {
        // Additional safe TLDs
        assert!(validate_domains(&["myapp.lan".into()]).is_ok());
        assert!(validate_domains(&["myapp.home".into()]).is_ok());
        assert!(validate_domains(&["myapp.corp".into()]).is_ok());
        assert!(validate_domains(&["myapp.intranet".into()]).is_ok());
        assert!(validate_domains(&["myapp.private".into()]).is_ok());
        assert!(validate_domains(&["myapp.devlocal".into()]).is_ok());
    }

    #[test]
    fn test_is_private_ip_v4() {
        use std::net::Ipv4Addr;

        // Loopback
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 255, 255, 255
        ))));

        // Private ranges
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Link-local
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));

        // Public (should be false)
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_private_ip_v6() {
        use std::net::Ipv6Addr;

        // Loopback
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Unique local (fc00::/7 - private IPv6)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));

        // Link-local (fe80::/10)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));

        // Public (should be false)
        assert!(!is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_ipv6_unique_local() {
        use std::net::Ipv6Addr;

        // fc00::/7 range (fc00:: to fdff::)
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 0
        )));
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfd12, 0x3456, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_unique_local(&Ipv6Addr::new(
            0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        )));

        // Not unique local
        assert!(!is_ipv6_unique_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_unique_local(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_ipv6_link_local() {
        use std::net::Ipv6Addr;

        // fe80::/10 range
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0xaabb, 0xccdd, 0xeeff, 0x1122
        )));
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        )));

        // Not link-local
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_cert_generate() {
        let ca = Ca::generate(365).expect("CA should be generated"); // CA valid for 365 days
        let result = Cert::generate(&ca, &["localhost".into()], 30)
            .expect("certificate should be generated");
        let cert = result.cert;

        assert!(!cert.pem.is_empty());
        assert!(!cert.key_pem.is_empty());
        assert_eq!(cert.domains, vec!["localhost".to_string()]);
        assert!(cert.pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(result.warning.is_none()); // No warning expected since CA outlives cert
    }

    #[test]
    fn test_cert_generate_localhost() {
        let ca = Ca::generate(365).expect("CA should be generated"); // CA valid for 365 days
        let result =
            Cert::generate_localhost(&ca, 30).expect("localhost certificate should be generated");
        let cert = result.cert;

        assert!(cert.domains.contains(&"localhost".to_string()));
        assert!(cert.domains.contains(&"*.localhost".to_string()));
        assert!(cert.domains.contains(&"127.0.0.1".to_string()));
        assert!(cert.domains.contains(&"::1".to_string()));
    }

    #[test]
    fn test_cert_generate_warning_when_outlives_ca() {
        let ca = Ca::generate(10).expect("CA should be generated"); // CA valid for 10 days
        let result = Cert::generate(&ca, &["localhost".into()], 30)
            .expect("certificate should be generated"); // Cert for 30 days

        assert!(result.warning.is_some());
        assert!(result
            .warning
            .expect("warning should be present when cert outlives CA")
            .contains("exceeds CA's remaining validity"));
    }

    #[test]
    fn test_validate_emails_valid() {
        assert!(validate_emails(&["user@example.com".into()]).is_ok());
        assert!(validate_emails(&["user.name@example.com".into()]).is_ok());
        assert!(validate_emails(&["user+tag@example.com".into()]).is_ok());
        assert!(validate_emails(&["user@sub.example.com".into()]).is_ok());
    }

    #[test]
    fn test_validate_emails_invalid() {
        assert!(validate_emails(&["invalid".into()]).is_err());
        assert!(validate_emails(&["@example.com".into()]).is_err());
        assert!(validate_emails(&["user@".into()]).is_err());
        assert!(validate_emails(&["user@.com".into()]).is_err());
    }

    #[test]
    fn test_validate_emails_edge_cases() {
        // Consecutive dots in local part
        assert!(validate_emails(&["user..name@example.com".into()]).is_err());
        // Leading dot in local part
        assert!(validate_emails(&[".user@example.com".into()]).is_err());
        // Trailing dot in local part
        assert!(validate_emails(&["user.@example.com".into()]).is_err());
        // Leading hyphen in domain
        assert!(validate_emails(&["user@-example.com".into()]).is_err());
        // Trailing hyphen in domain
        assert!(validate_emails(&["user@example-.com".into()]).is_err());
        // Double hyphen in domain (allowed, e.g., xn-- for punycode)
        assert!(validate_emails(&["user@ex--ample.com".into()]).is_ok());
    }

    #[test]
    fn test_validate_emails_empty() {
        // Empty list should be OK (no emails to validate)
        assert!(validate_emails(&[]).is_ok());
    }

    #[test]
    fn test_cert_generate_smime() {
        let ca = Ca::generate(365).expect("CA should be generated");
        let result = Cert::generate_smime(&ca, &["user@example.com".into()], &[], 30)
            .expect("S/MIME certificate should be generated");
        let cert = result.cert;

        assert!(!cert.pem.is_empty());
        assert!(!cert.key_pem.is_empty());
        assert!(cert.domains.contains(&"user@example.com".to_string()));
        assert!(cert.pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_cert_generate_smime_with_domains() {
        let ca = Ca::generate(365).expect("CA should be generated");
        let result =
            Cert::generate_smime(&ca, &["user@example.com".into()], &["localhost".into()], 30)
                .expect("S/MIME certificate with domains should be generated");
        let cert = result.cert;

        // Should contain both email and domain
        assert!(cert.domains.contains(&"user@example.com".to_string()));
        assert!(cert.domains.contains(&"localhost".to_string()));
    }

    #[test]
    fn test_cert_generate_smime_multiple_emails() {
        let ca = Ca::generate(365).expect("CA should be generated");
        let result = Cert::generate_smime(
            &ca,
            &["user1@example.com".into(), "user2@example.com".into()],
            &[],
            30,
        )
        .expect("S/MIME certificate with multiple emails should be generated");
        let cert = result.cert;

        assert!(cert.domains.contains(&"user1@example.com".to_string()));
        assert!(cert.domains.contains(&"user2@example.com".to_string()));
    }

    #[test]
    fn test_cert_generate_smime_requires_email() {
        let ca = Ca::generate(365).expect("CA should be generated");
        // Should fail with empty email list
        let result = Cert::generate_smime(&ca, &[], &[], 30);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_csr_validates_domains() {
        use std::io::Write;

        let ca = Ca::generate(365).expect("CA should be generated");

        // Create a CSR for a valid localhost domain
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.subject_alt_names.push(SanType::DnsName(
            "localhost"
                .to_string()
                .try_into()
                .expect("localhost should be a valid DNS name"),
        ));

        let key_pair = KeyPair::generate().expect("key pair should be generated");
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR should be serialized");
        let csr_pem = csr.pem().expect("CSR PEM should be generated");

        // Write CSR to a temp file
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let csr_path = temp_dir.path().join("valid.csr");
        let mut file = std::fs::File::create(&csr_path).expect("CSR file should be created");
        file.write_all(csr_pem.as_bytes())
            .expect("CSR should be written to file");

        // This should succeed
        let result = Cert::sign_csr(&ca, &csr_path, 30);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_csr_rejects_public_domains() {
        use std::io::Write;

        let ca = Ca::generate(365).expect("CA should be generated");

        // Create a CSR for a PUBLIC domain (this should be rejected!)
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "google.com");
        params.subject_alt_names.push(SanType::DnsName(
            "google.com"
                .to_string()
                .try_into()
                .expect("google.com should be a valid DNS name"),
        ));
        params.subject_alt_names.push(SanType::DnsName(
            "*.google.com"
                .to_string()
                .try_into()
                .expect("*.google.com should be a valid DNS name"),
        ));

        let key_pair = KeyPair::generate().expect("key pair should be generated");
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR should be serialized");
        let csr_pem = csr.pem().expect("CSR PEM should be generated");

        // Write CSR to a temp file
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let csr_path = temp_dir.path().join("malicious.csr");
        let mut file = std::fs::File::create(&csr_path).expect("CSR file should be created");
        file.write_all(csr_pem.as_bytes())
            .expect("CSR should be written to file");

        // This should FAIL - we should not sign CSRs for public domains
        let result = Cert::sign_csr(&ca, &csr_path, 30);
        assert!(result.is_err());
        match result.expect_err("signing public domain CSR should fail") {
            Error::InvalidDomain { domain, .. } => {
                assert!(domain.contains("google.com"));
            }
            e => panic!("Expected InvalidDomain error, got: {:?}", e),
        }
    }

    #[test]
    fn test_sign_csr_rejects_public_ip() {
        use std::io::Write;

        let ca = Ca::generate(365).expect("CA should be generated");

        // Create a CSR for a public IP address (this should be rejected!)
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "8.8.8.8");
        params.subject_alt_names.push(SanType::IpAddress(
            "8.8.8.8"
                .parse()
                .expect("8.8.8.8 should be a valid IP address"),
        ));

        let key_pair = KeyPair::generate().expect("key pair should be generated");
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR should be serialized");
        let csr_pem = csr.pem().expect("CSR PEM should be generated");

        // Write CSR to a temp file
        let temp_dir = tempfile::tempdir().expect("temp directory should be created");
        let csr_path = temp_dir.path().join("public_ip.csr");
        let mut file = std::fs::File::create(&csr_path).expect("CSR file should be created");
        file.write_all(csr_pem.as_bytes())
            .expect("CSR should be written to file");

        // This should FAIL - we should not sign CSRs for public IPs
        let result = Cert::sign_csr(&ca, &csr_path, 30);
        assert!(result.is_err());
    }
}

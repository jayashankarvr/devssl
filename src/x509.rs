// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

//! Parse X.509 certificates without shelling out to openssl.

use crate::error::{Error, Result};
use std::path::Path;
use x509_parser::prelude::*;

/// Certificate type based on Extended Key Usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// TLS server authentication (OID 1.3.6.1.5.5.7.3.1)
    Server,
    /// TLS client authentication (OID 1.3.6.1.5.5.7.3.2)
    Client,
    /// S/MIME email protection (OID 1.3.6.1.5.5.7.3.4)
    Smime,
    /// Unknown or no EKU
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub not_after_timestamp: i64,
    pub not_before_timestamp: i64,
    pub common_name: Option<String>,
    pub subject_alt_names: Vec<String>,
    /// Email addresses from RFC822Name SANs
    pub emails: Vec<String>,
    pub is_ca: bool,
    /// Certificate type based on Extended Key Usage
    pub cert_type: CertType,
}

impl CertInfo {
    pub fn expiry_string(&self) -> String {
        match ::time::OffsetDateTime::from_unix_timestamp(self.not_after_timestamp) {
            Ok(dt) => format!("{}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day()),
            Err(_) => "Invalid date".to_string(),
        }
    }

    pub fn days_remaining(&self) -> i64 {
        let now = ::time::OffsetDateTime::now_utc();
        match ::time::OffsetDateTime::from_unix_timestamp(self.not_after_timestamp) {
            Ok(expiry) => (expiry - now).whole_days(),
            Err(_) => -1, // Treat invalid timestamps as expired
        }
    }

    pub fn is_expired(&self) -> bool {
        self.days_remaining() < 0
    }
}

pub fn parse_cert_file(path: &Path) -> Result<CertInfo> {
    let pem_data = std::fs::read_to_string(path).map_err(|e| Error::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_cert_pem(&pem_data)
}

pub fn parse_cert_pem(pem_str: &str) -> Result<CertInfo> {
    let pem = ::pem::parse(pem_str)
        .map_err(|e| Error::CertParse(format!("Failed to parse PEM: {}", e)))?;

    if pem.tag() != "CERTIFICATE" {
        return Err(Error::CertParse(format!(
            "Expected CERTIFICATE, got {}",
            pem.tag()
        )));
    }

    let (_, cert) = X509Certificate::from_der(pem.contents())
        .map_err(|e| Error::CertParse(format!("Invalid X.509: {}", e)))?;

    let not_before_timestamp = cert.validity().not_before.timestamp();
    let not_after_timestamp = cert.validity().not_after.timestamp();

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from);

    let mut subject_alt_names = Vec::new();
    let mut emails = Vec::new();
    let mut is_ca = false;
    let mut cert_type = CertType::Unknown;

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => subject_alt_names.push(dns.to_string()),
                        GeneralName::IPAddress(ip_bytes) if ip_bytes.len() == 4 => {
                            let ip = std::net::Ipv4Addr::new(
                                ip_bytes[0],
                                ip_bytes[1],
                                ip_bytes[2],
                                ip_bytes[3],
                            );
                            subject_alt_names.push(ip.to_string());
                        }
                        GeneralName::IPAddress(ip_bytes) if ip_bytes.len() == 16 => {
                            if let Ok(bytes) = <[u8; 16]>::try_from(*ip_bytes) {
                                subject_alt_names.push(std::net::Ipv6Addr::from(bytes).to_string());
                            }
                        }
                        GeneralName::RFC822Name(email) => {
                            emails.push(email.to_string());
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                // Determine cert type based on EKU
                // Priority: EmailProtection > ClientAuth > ServerAuth
                // (S/MIME certs may have both email and client auth)
                if eku.email_protection {
                    cert_type = CertType::Smime;
                } else if eku.client_auth {
                    cert_type = CertType::Client;
                } else if eku.server_auth {
                    cert_type = CertType::Server;
                }
            }
            _ => {}
        }
    }

    Ok(CertInfo {
        not_after_timestamp,
        not_before_timestamp,
        common_name,
        subject_alt_names,
        emails,
        is_ca,
        cert_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use crate::cert::Cert;

    #[test]
    fn test_parse_cert_pem() {
        // Generate a test certificate
        let ca = Ca::generate(30).unwrap();
        let result = Cert::generate(&ca, &["localhost".into()], 30).unwrap();

        // Parse it back
        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert!(info.days_remaining() >= 29);
        assert!(info.days_remaining() <= 30);
        assert!(!info.is_expired());
        assert_eq!(info.common_name, Some("localhost".to_string()));
        // End-entity certificates should NOT have CA:TRUE
        assert!(!info.is_ca);
    }

    #[test]
    fn test_parse_ca_cert() {
        let ca = Ca::generate(365).unwrap();

        let info = parse_cert_pem(&ca.cert_pem).unwrap();

        assert!(info.days_remaining() >= 364);
        assert_eq!(info.common_name, Some("devssl Local CA".to_string()));
        // CA certificates should have BasicConstraints CA:TRUE
        assert!(info.is_ca);
    }

    #[test]
    fn test_expiry_string() {
        let ca = Ca::generate(30).unwrap();
        let info = parse_cert_pem(&ca.cert_pem).unwrap();

        let expiry = info.expiry_string();
        // Should be in YYYY-MM-DD format
        assert!(expiry.len() == 10);
        assert!(expiry.chars().nth(4) == Some('-'));
        assert!(expiry.chars().nth(7) == Some('-'));
    }

    #[test]
    fn test_detect_server_cert_type() {
        let ca = Ca::generate(30).unwrap();
        let result = Cert::generate(&ca, &["localhost".into()], 30).unwrap();

        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert_eq!(info.cert_type, CertType::Server);
        assert!(info.emails.is_empty());
    }

    #[test]
    fn test_detect_client_cert_type() {
        let ca = Ca::generate(30).unwrap();
        let result = Cert::generate_client(&ca, &["localhost".into()], 30).unwrap();

        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert_eq!(info.cert_type, CertType::Client);
        assert!(info.emails.is_empty());
    }

    #[test]
    fn test_detect_smime_cert_type() {
        let ca = Ca::generate(30).unwrap();
        let result = Cert::generate_smime(&ca, &["user@example.com".into()], &[], 30).unwrap();

        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert_eq!(info.cert_type, CertType::Smime);
        assert_eq!(info.emails, vec!["user@example.com".to_string()]);
    }

    #[test]
    fn test_smime_cert_with_multiple_emails() {
        let ca = Ca::generate(30).unwrap();
        let result = Cert::generate_smime(
            &ca,
            &["user1@example.com".into(), "user2@example.com".into()],
            &[],
            30,
        )
        .unwrap();

        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert_eq!(info.cert_type, CertType::Smime);
        assert!(info.emails.contains(&"user1@example.com".to_string()));
        assert!(info.emails.contains(&"user2@example.com".to_string()));
    }

    #[test]
    fn test_smime_cert_with_domains() {
        let ca = Ca::generate(30).unwrap();
        let result =
            Cert::generate_smime(&ca, &["user@example.com".into()], &["localhost".into()], 30)
                .unwrap();

        let info = parse_cert_pem(&result.cert.pem).unwrap();

        assert_eq!(info.cert_type, CertType::Smime);
        assert!(info.emails.contains(&"user@example.com".to_string()));
        assert!(info.subject_alt_names.contains(&"localhost".to_string()));
    }
}

// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

//! Local CA and certificate generation for development HTTPS.
//!
//! ```rust,no_run
//! use devssl::{Ca, Cert, Paths, Config};
//!
//! let paths = Paths::new()?;
//! let config = Config::load(&paths.config)?;
//!
//! let ca = Ca::generate(config.ca_days)?;
//! ca.save(&paths)?;
//!
//! let result = Cert::generate_localhost(&ca, config.cert_days)?;
//! result.cert.save(&paths, "localhost")?;
//! # Ok::<(), devssl::Error>(())
//! ```

/// Certificate Authority management.
pub mod ca;
/// Certificate generation and management.
pub mod cert;
/// Configuration handling.
pub mod config;
/// Background daemon for certificate renewal.
pub mod daemon;
/// Error types.
pub mod error;
/// Filesystem utilities.
pub mod fs;
/// HTTPS proxy server.
pub mod proxy;
/// System trust store management.
pub mod trust;
/// X.509 certificate parsing.
pub mod x509;

pub use ca::{
    change_key_password, decrypt_existing_key, encrypt_existing_key, Ca, CA_COMMON_NAME,
    CA_ORG_NAME,
};
pub use cert::{
    validate_days, validate_emails, Cert, CertGenerateResult, CsrSignResult, LOCALHOST_DOMAINS,
    LOCALHOST_IPS, MAX_CERT_DAYS,
};
pub use config::{Config, Paths};
pub use error::{Error, Result};
pub use fs::{is_reserved_name, path_to_str, write_secret_file, RESERVED_NAMES};
pub use proxy::{load_tls_config, run_proxy, run_proxy_with_redirect, RedirectConfig};
pub use trust::{get_trust_store, TrustStore, TrustStoreFilter};
pub use x509::{parse_cert_file, parse_cert_pem, CertInfo, CertType};

// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use crate::error::{Error, Result};
use std::path::Path;

/// Validate a path for use in trust store operations.
/// Prevents command injection and path traversal attacks.
pub fn validate_cert_path(path: &Path) -> Result<std::path::PathBuf> {
    // Path must exist
    if !path.exists() {
        return Err(Error::ReadFile {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "File not found"),
        });
    }

    // Must be a regular file, not a directory or symlink to directory
    if !path.is_file() {
        return Err(Error::TrustStore(format!(
            "Path is not a regular file: {}",
            path.display()
        )));
    }

    // Canonicalize to resolve symlinks and get absolute path
    // This prevents symlink attacks where attacker replaces file after validation
    let canonical = path.canonicalize().map_err(|e| Error::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Convert to string to check for dangerous characters
    let path_str = canonical
        .to_str()
        .ok_or_else(|| Error::TrustStore("Path contains invalid UTF-8 characters".to_string()))?;

    // Reject paths with shell metacharacters that could enable command injection
    const DANGEROUS_CHARS: &[char] = &[
        ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!', '~', '*', '?', '#',
        '\n', '\r', '\0',
    ];

    for c in DANGEROUS_CHARS {
        if path_str.contains(*c) {
            return Err(Error::TrustStore(format!(
                "Path contains dangerous character '{}': {}",
                c,
                path.display()
            )));
        }
    }

    // Reject paths starting with dash (could be interpreted as option)
    if path_str.starts_with('-') {
        return Err(Error::TrustStore(format!(
            "Path cannot start with dash: {}",
            path.display()
        )));
    }

    Ok(canonical)
}

/// Validate an environment variable path (HOME, JAVA_HOME, etc.)
/// Returns canonicalized path or None if invalid/unsafe.
pub fn validate_env_path(env_var: &str) -> Option<std::path::PathBuf> {
    let value = std::env::var(env_var).ok()?;
    let path = std::path::PathBuf::from(&value);

    // Must exist and be a directory
    if !path.is_dir() {
        return None;
    }

    // Canonicalize to resolve symlinks
    let canonical = path.canonicalize().ok()?;

    // Check for dangerous characters in the path
    let path_str = canonical.to_str()?;
    const DANGEROUS_CHARS: &[char] = &[
        ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!', '~', '*', '?', '#',
        '\n', '\r', '\0',
    ];

    for c in DANGEROUS_CHARS {
        if path_str.contains(*c) {
            return None;
        }
    }

    Some(canonical)
}

pub trait TrustStore {
    fn add_ca(&self, cert_path: &Path) -> Result<()>;
    fn remove_ca(&self, cert_path: &Path) -> Result<()>;
    fn is_trusted(&self, cert_path: &Path) -> Result<bool>;
    fn name(&self) -> &'static str;
}

/// Represents which trust stores to use, controlled by DEVSSL_TRUST_STORES env var.
/// If not set, all available trust stores are used (backwards compatible).
#[derive(Debug, Clone)]
pub struct TrustStoreFilter {
    pub system: bool,
    pub nss: bool,
    pub java: bool,
}

impl Default for TrustStoreFilter {
    fn default() -> Self {
        // By default, enable all trust stores
        Self {
            system: true,
            nss: true,
            java: true,
        }
    }
}

impl TrustStoreFilter {
    /// Parse the DEVSSL_TRUST_STORES environment variable.
    /// Format: comma-separated list of trust store names (system, nss, java).
    /// If not set or empty, returns default (all enabled).
    pub fn from_env() -> Self {
        match std::env::var("DEVSSL_TRUST_STORES") {
            Ok(value) if !value.trim().is_empty() => Self::parse(&value),
            _ => Self::default(),
        }
    }

    /// Parse a comma-separated list of trust store names.
    /// Valid names: system, nss, java (case-insensitive).
    /// Unknown names are ignored.
    /// Empty string returns default (all enabled).
    pub fn parse(value: &str) -> Self {
        // Empty string means "use defaults" - same as from_env() behavior
        if value.trim().is_empty() {
            return Self::default();
        }

        let mut filter = Self {
            system: false,
            nss: false,
            java: false,
        };

        for store in value.split(',') {
            match store.trim().to_lowercase().as_str() {
                "system" => filter.system = true,
                "nss" => filter.nss = true,
                "java" => filter.java = true,
                _ => {} // Ignore unknown store names
            }
        }

        filter
    }
}

pub fn get_trust_store() -> Box<dyn TrustStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsTrustStore)
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxTrustStore::detect())
    }

    #[cfg(windows)]
    {
        Box::new(windows::WindowsTrustStore)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Box::new(NullTrustStore)
    }
}

pub struct NullTrustStore;

impl TrustStore for NullTrustStore {
    fn add_ca(&self, _cert_path: &Path) -> Result<()> {
        eprintln!("Warning: Trust store not supported on this platform.");
        eprintln!("You may need to manually add the CA certificate to your browser/system.");
        Ok(())
    }

    fn remove_ca(&self, _cert_path: &Path) -> Result<()> {
        Ok(())
    }

    fn is_trusted(&self, _cert_path: &Path) -> Result<bool> {
        Ok(false)
    }

    fn name(&self) -> &'static str {
        "Unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_store_filter_default() {
        // Test Default trait implementation
        let filter = TrustStoreFilter::default();
        assert!(filter.system);
        assert!(filter.nss);
        assert!(filter.java);
    }

    #[test]
    fn test_trust_store_filter_system_only() {
        let filter = TrustStoreFilter::parse("system");
        assert!(filter.system);
        assert!(!filter.nss);
        assert!(!filter.java);
    }

    #[test]
    fn test_trust_store_filter_multiple() {
        let filter = TrustStoreFilter::parse("system,nss");
        assert!(filter.system);
        assert!(filter.nss);
        assert!(!filter.java);
    }

    #[test]
    fn test_trust_store_filter_with_spaces() {
        let filter = TrustStoreFilter::parse(" system , nss , java ");
        assert!(filter.system);
        assert!(filter.nss);
        assert!(filter.java);
    }

    #[test]
    fn test_trust_store_filter_case_insensitive() {
        let filter = TrustStoreFilter::parse("SYSTEM,NSS,Java");
        assert!(filter.system);
        assert!(filter.nss);
        assert!(filter.java);
    }

    #[test]
    fn test_trust_store_filter_ignores_unknown() {
        let filter = TrustStoreFilter::parse("system,unknown,fake");
        assert!(filter.system);
        assert!(!filter.nss);
        assert!(!filter.java);
    }

    #[test]
    fn test_trust_store_filter_empty_string() {
        // Empty string returns default (all enabled) - consistent with from_env() behavior
        let filter = TrustStoreFilter::parse("");
        assert!(filter.system);
        assert!(filter.nss);
        assert!(filter.java);
    }
}

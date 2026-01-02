// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Current config file version. Increment when making breaking changes.
const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Config file version for future migration support
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    #[serde(default = "default_cert_days")]
    pub cert_days: u32,
    #[serde(default = "default_ca_days")]
    pub ca_days: u32,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}

/// Configuration for the auto-renewal daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// How often to check certificates (in hours)
    #[serde(default = "default_check_interval_hours")]
    pub check_interval_hours: u32,
    /// Renew certificates expiring within this many days
    #[serde(default = "default_renew_within_days")]
    pub renew_within_days: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            check_interval_hours: default_check_interval_hours(),
            renew_within_days: default_renew_within_days(),
        }
    }
}

fn default_check_interval_hours() -> u32 {
    1
}

fn default_renew_within_days() -> u32 {
    7
}

fn default_cert_days() -> u32 {
    365
}

fn default_ca_days() -> u32 {
    3650
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
            cert_days: default_cert_days(),
            ca_days: default_ca_days(),
            daemon: DaemonConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub base: PathBuf,
    pub ca_key: PathBuf,
    pub ca_key_enc: PathBuf,
    pub ca_cert: PathBuf,
    pub config: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let base = Self::base_dir()?;
        Ok(Self {
            ca_key: base.join("ca.key"),
            ca_key_enc: base.join("ca.key.enc"),
            ca_cert: base.join("ca.crt"),
            config: base.join("config.toml"),
            base,
        })
    }

    /// Sanitize a domain name for safe use in file paths.
    /// Returns an error if the domain contains unsafe characters.
    /// Wildcard domains (e.g., `*.localhost`) are supported by replacing `*` with `_wildcard_`.
    fn sanitize_domain_for_filename(domain: &str) -> Result<String> {
        // Reject empty domains
        if domain.is_empty() {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain cannot be empty".into(),
            });
        }

        // Reject null bytes
        if domain.contains('\0') {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain contains null byte".into(),
            });
        }

        // Reject percent-encoded characters (potential path traversal bypass)
        if domain.contains('%') {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain contains percent encoding (potential path traversal)".into(),
            });
        }

        // Reject path traversal sequences
        if domain.contains("..") {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain contains path traversal sequence".into(),
            });
        }

        // Reject path separators
        if domain.contains('/') || domain.contains('\\') {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain contains path separator".into(),
            });
        }

        // Reject leading/trailing dots (invalid filenames on some systems)
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(Error::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain cannot start or end with a dot".into(),
            });
        }

        // Replace wildcard character with safe placeholder for filenames
        let sanitized = domain.replace('*', "_wildcard_");

        // Only allow alphanumeric, dots, hyphens, underscores
        for c in sanitized.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' {
                return Err(Error::InvalidDomain {
                    domain: domain.to_string(),
                    reason: format!("domain contains invalid character: '{}'", c),
                });
            }
        }

        Ok(sanitized)
    }

    fn base_dir() -> Result<PathBuf> {
        // Check for DEVSSL_ROOT environment variable first
        if let Ok(custom_root) = std::env::var("DEVSSL_ROOT") {
            let path = PathBuf::from(&custom_root);

            // Must be an absolute path
            if !path.is_absolute() {
                return Err(Error::Config(format!(
                    "DEVSSL_ROOT must be an absolute path, got: {}",
                    custom_root
                )));
            }

            // Warn about potentially dangerous locations (but allow them)
            let path_str = custom_root.to_lowercase();
            if path_str.starts_with("/etc")
                || path_str.starts_with("/usr")
                || path_str.starts_with("/bin")
                || path_str.starts_with("/sbin")
                || path_str.starts_with("/lib")
                || path_str.starts_with("/var")
                || path_str == "/tmp"
                || path_str.starts_with("/tmp/")
            {
                eprintln!(
                    "Warning: DEVSSL_ROOT points to system directory: {}",
                    custom_root
                );
                eprintln!("         Consider using a user-specific directory instead.");
            }

            return Ok(path);
        }

        // When running with sudo, use the original user's home directory
        #[cfg(unix)]
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            // Validate username to prevent injection
            if sudo_user
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                let user_home = PathBuf::from("/home").join(&sudo_user);
                let data_dir = user_home.join(".local").join("share").join("devssl");
                if user_home.exists() && user_home.is_dir() {
                    return Ok(data_dir);
                }
            }
        }

        if let Some(proj_dirs) = ProjectDirs::from("", "", "devssl") {
            Ok(proj_dirs.data_dir().to_path_buf())
        } else if let Some(base_dirs) = BaseDirs::new() {
            // Use BaseDirs for home directory detection (works in containers/CI)
            #[cfg(windows)]
            {
                Ok(base_dirs.data_local_dir().join("devssl"))
            }
            #[cfg(not(windows))]
            {
                Ok(base_dirs.home_dir().join(".devssl"))
            }
        } else {
            // Ultimate fallback to /tmp for extreme cases (e.g., no home directory)
            eprintln!("Warning: Could not determine home directory, using /tmp/.devssl");
            eprintln!(
                "         Set DEVSSL_ROOT environment variable to specify a custom location."
            );
            Ok(PathBuf::from("/tmp/.devssl"))
        }
    }

    pub fn cert_path(&self, domain: &str) -> Result<PathBuf> {
        let safe_domain = Self::sanitize_domain_for_filename(domain)?;
        Ok(self.base.join(format!("{}.crt", safe_domain)))
    }

    pub fn key_path(&self, domain: &str) -> Result<PathBuf> {
        let safe_domain = Self::sanitize_domain_for_filename(domain)?;
        Ok(self.base.join(format!("{}.key", safe_domain)))
    }

    pub fn ensure_dir(&self) -> Result<()> {
        if !self.base.exists() {
            std::fs::create_dir_all(&self.base).map_err(|e| Error::CreateDir {
                path: self.base.clone(),
                source: e,
            })?;
        }
        Ok(())
    }

    pub fn ca_exists(&self) -> bool {
        (self.ca_key.exists() || self.ca_key_enc.exists()) && self.ca_cert.exists()
    }

    /// Check if the CA key is encrypted
    pub fn ca_key_is_encrypted(&self) -> bool {
        self.ca_key_enc.exists()
    }

    /// Path to the daemon PID file
    pub fn pid_path(&self) -> PathBuf {
        self.base.join("daemon.pid")
    }

    /// Path to the daemon log file
    pub fn log_path(&self) -> PathBuf {
        self.base.join("daemon.log")
    }

    /// Path to the secure password file (temporary, deleted after read)
    pub fn password_file_path(&self) -> PathBuf {
        self.base.join(".daemon_password")
    }

    /// Ensure certificate exists and return the path
    pub fn ensure_cert_exists(&self, name: &str) -> crate::error::Result<PathBuf> {
        let cert_path = self.cert_path(name)?;
        if !cert_path.exists() {
            return Err(crate::error::Error::CertificateNotFound {
                name: name.to_string(),
            });
        }
        Ok(cert_path)
    }

    /// Ensure key file exists and return the path
    pub fn ensure_key_exists(&self, name: &str) -> crate::error::Result<PathBuf> {
        let key_path = self.key_path(name)?;
        if !key_path.exists() {
            return Err(crate::error::Error::CertificateNotFound {
                name: name.to_string(),
            });
        }
        Ok(key_path)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path).map_err(|e| Error::ReadFile {
                path: path.to_path_buf(),
                source: e,
            })?;
            toml::from_str(&content).map_err(|e| Error::Config(e.to_string()))?
        } else {
            Self::default()
        };

        // Migrate config if needed
        let migrated = Self::migrate(&mut config)?;

        // Save migrated config back to disk
        if migrated && path.exists() {
            config.save(path)?;
        }

        // Validate config values
        config.validate()?;

        Ok(config)
    }

    /// Migrate config from older versions to current version.
    /// Returns true if config was modified.
    fn migrate(config: &mut Self) -> Result<bool> {
        let original_version = config.config_version;

        // No migration needed if already at current version
        if config.config_version >= CONFIG_VERSION {
            return Ok(false);
        }

        // Perform migrations in order, stepping through each version
        let mut current_version = config.config_version;

        while current_version < CONFIG_VERSION {
            match current_version {
                0 => {
                    // v0 -> v1: Add daemon config defaults
                    // Older configs might not have daemon config, which is handled by serde defaults
                    // But we should ensure sensible values
                    if config.daemon.check_interval_hours == 0 {
                        config.daemon.check_interval_hours = default_check_interval_hours();
                    }
                    if config.daemon.renew_within_days == 0 {
                        config.daemon.renew_within_days = default_renew_within_days();
                    }
                    current_version = 1;
                }
                1 => {
                    // v1 -> v2: Future migration placeholder
                    current_version = 2;
                }
                _ => {
                    // Unknown future version - skip it
                    eprintln!(
                        "Warning: Skipping unknown config version {}",
                        current_version
                    );
                    current_version += 1;
                }
            }
        }

        // Update to current version
        config.config_version = CONFIG_VERSION;
        Ok(current_version != original_version)
    }

    fn validate(&self) -> Result<()> {
        use crate::cert::{validate_days, MAX_CERT_DAYS};

        // Validate config version (warn if newer, could add migration logic here)
        if self.config_version > CONFIG_VERSION {
            eprintln!(
                "Warning: config.toml version {} is newer than supported version {}.",
                self.config_version, CONFIG_VERSION
            );
            eprintln!("         Some settings may not be recognized. Consider upgrading devssl.");
        }

        // Validate cert_days
        validate_days(self.cert_days)?;

        // Validate ca_days (same rules apply)
        if self.ca_days == 0 {
            return Err(Error::InvalidDays("ca_days cannot be 0".into()));
        }
        if self.ca_days > MAX_CERT_DAYS {
            return Err(Error::InvalidDays(format!(
                "ca_days cannot exceed {} (10 years)",
                MAX_CERT_DAYS
            )));
        }

        // Validate DaemonConfig
        if self.daemon.check_interval_hours < 1 {
            return Err(Error::Config(
                "daemon.check_interval_hours must be at least 1".into(),
            ));
        }
        // Max check interval: 168 hours (1 week) - checking less frequently risks missing renewals
        if self.daemon.check_interval_hours > 168 {
            return Err(Error::Config(
                "daemon.check_interval_hours must be at most 168 (1 week)".into(),
            ));
        }
        if self.daemon.renew_within_days < 1 {
            return Err(Error::Config(
                "daemon.renew_within_days must be at least 1".into(),
            ));
        }
        // Max renew window: 90 days (3 months) - certs are typically 365 days
        if self.daemon.renew_within_days > 90 {
            return Err(Error::Config(
                "daemon.renew_within_days must be at most 90".into(),
            ));
        }

        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| Error::WriteFile {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.cert_days, 365);
        assert_eq!(config.ca_days, 3650);
    }

    #[test]
    fn test_config_load_missing_file() {
        let path = PathBuf::from("/nonexistent/config.toml");
        let config =
            Config::load(&path).expect("Config should load with defaults for missing file");

        // Should return defaults
        assert_eq!(config.cert_days, 365);
        assert_eq!(config.ca_days, 3650);
    }

    #[test]
    fn test_config_load_custom_values() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "cert_days = 7").expect("write cert_days should succeed");
        writeln!(file, "ca_days = 365").expect("write ca_days should succeed");

        let config = Config::load(file.path()).expect("Config should load successfully");
        assert_eq!(config.cert_days, 7);
        assert_eq!(config.ca_days, 365);
    }

    #[test]
    fn test_config_load_partial() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "cert_days = 14").expect("write cert_days should succeed");
        // ca_days missing - should use default

        let config = Config::load(file.path()).expect("Config should load with partial values");
        assert_eq!(config.cert_days, 14);
        assert_eq!(config.ca_days, 3650); // default
    }

    #[test]
    fn test_config_save_and_load() {
        let file = NamedTempFile::new().expect("temp file should be created");
        let config = Config {
            config_version: 1,
            cert_days: 90,
            ca_days: 730,
            daemon: DaemonConfig::default(),
        };

        config
            .save(file.path())
            .expect("Config should save successfully");
        let loaded = Config::load(file.path()).expect("Config should load after save");

        assert_eq!(loaded.config_version, 1);
        assert_eq!(loaded.cert_days, 90);
        assert_eq!(loaded.ca_days, 730);
    }

    #[test]
    fn test_config_invalid_cert_days_zero() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "cert_days = 0").expect("write cert_days should succeed");

        let result = Config::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_cert_days_too_large() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "cert_days = 999999").expect("write cert_days should succeed");

        let result = Config::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_ca_days_zero() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "ca_days = 0").expect("write ca_days should succeed");

        let result = Config::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_daemon_check_interval_zero() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "[daemon]").expect("write daemon section should succeed");
        writeln!(file, "check_interval_hours = 0")
            .expect("write check_interval_hours should succeed");

        let result = Config::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_daemon_renew_within_days_zero() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "[daemon]").expect("write daemon section should succeed");
        writeln!(file, "renew_within_days = 0").expect("write renew_within_days should succeed");

        let result = Config::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_paths_respects_devssl_root_env() {
        // Save the original value if set
        let original = std::env::var("DEVSSL_ROOT").ok();

        // Use a temp directory for cross-platform compatibility
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let custom_path = temp_dir.path().join("devssl");
        std::env::set_var("DEVSSL_ROOT", &custom_path);

        let paths = Paths::new().expect("Paths should be created from DEVSSL_ROOT");
        assert_eq!(paths.base, custom_path);
        assert_eq!(paths.ca_cert, custom_path.join("ca.crt"));
        assert_eq!(paths.ca_key, custom_path.join("ca.key"));
        assert_eq!(paths.ca_key_enc, custom_path.join("ca.key.enc"));

        // Restore original value
        match original {
            Some(val) => std::env::set_var("DEVSSL_ROOT", val),
            None => std::env::remove_var("DEVSSL_ROOT"),
        }
    }

    #[test]
    fn test_sanitize_domain_valid() {
        // Valid domains should pass
        assert!(Paths::sanitize_domain_for_filename("example.com").is_ok());
        assert!(Paths::sanitize_domain_for_filename("sub.example.com").is_ok());
        assert!(Paths::sanitize_domain_for_filename("my-domain.com").is_ok());
        assert!(Paths::sanitize_domain_for_filename("my_domain.com").is_ok());
        assert!(Paths::sanitize_domain_for_filename("localhost").is_ok());
        assert!(Paths::sanitize_domain_for_filename("test123").is_ok());
    }

    #[test]
    fn test_sanitize_domain_rejects_empty() {
        assert!(Paths::sanitize_domain_for_filename("").is_err());
    }

    #[test]
    fn test_sanitize_domain_rejects_path_traversal() {
        assert!(Paths::sanitize_domain_for_filename("..").is_err());
        assert!(Paths::sanitize_domain_for_filename("../etc/passwd").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo/../bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("a..b").is_err());
    }

    #[test]
    fn test_sanitize_domain_rejects_path_separators() {
        assert!(Paths::sanitize_domain_for_filename("/etc/passwd").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo/bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("C:\\Windows").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo\\bar").is_err());
    }

    #[test]
    fn test_sanitize_domain_rejects_null_bytes() {
        assert!(Paths::sanitize_domain_for_filename("foo\0bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("\0").is_err());
    }

    #[test]
    fn test_sanitize_domain_rejects_invalid_chars() {
        assert!(Paths::sanitize_domain_for_filename("foo:bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo?bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo<bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo>bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo|bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo\"bar").is_err());
        assert!(Paths::sanitize_domain_for_filename("foo bar").is_err());
    }

    #[test]
    fn test_sanitize_domain_wildcard() {
        // Wildcard domains should be allowed with * replaced by _wildcard_
        assert_eq!(
            Paths::sanitize_domain_for_filename("*.localhost")
                .expect("wildcard localhost should be valid"),
            "_wildcard_.localhost"
        );
        assert_eq!(
            Paths::sanitize_domain_for_filename("*.example.com")
                .expect("wildcard example.com should be valid"),
            "_wildcard_.example.com"
        );
        assert_eq!(
            Paths::sanitize_domain_for_filename("foo*bar")
                .expect("embedded wildcard should be valid"),
            "foo_wildcard_bar"
        );
    }

    #[test]
    fn test_cert_path_sanitizes_domain() {
        let original = std::env::var("DEVSSL_ROOT").ok();

        // Use a temp directory for cross-platform compatibility
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let test_path = temp_dir.path().join("test");
        std::env::set_var("DEVSSL_ROOT", &test_path);

        let paths = Paths::new().expect("Paths should be created from DEVSSL_ROOT");

        // Valid domain should work
        let cert = paths
            .cert_path("example.com")
            .expect("example.com should be a valid domain");
        assert_eq!(cert, test_path.join("example.com.crt"));

        // Malicious domain should fail
        assert!(paths.cert_path("../../../etc/passwd").is_err());
        assert!(paths.cert_path("foo/bar").is_err());

        match original {
            Some(val) => std::env::set_var("DEVSSL_ROOT", val),
            None => std::env::remove_var("DEVSSL_ROOT"),
        }
    }

    #[test]
    fn test_key_path_sanitizes_domain() {
        let original = std::env::var("DEVSSL_ROOT").ok();

        // Use a temp directory for cross-platform compatibility
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let test_path = temp_dir.path().join("test");
        std::env::set_var("DEVSSL_ROOT", &test_path);

        let paths = Paths::new().expect("Paths should be created from DEVSSL_ROOT");

        // Valid domain should work
        let key = paths
            .key_path("example.com")
            .expect("example.com should be a valid domain");
        assert_eq!(key, test_path.join("example.com.key"));

        // Malicious domain should fail
        assert!(paths.key_path("../../../etc/passwd").is_err());
        assert!(paths.key_path("foo\\bar").is_err());

        match original {
            Some(val) => std::env::set_var("DEVSSL_ROOT", val),
            None => std::env::remove_var("DEVSSL_ROOT"),
        }
    }
}

// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::ca::CA_COMMON_NAME;
use crate::error::{Error, Result};
use crate::fs::path_to_str;
use crate::trust::{validate_cert_path, validate_env_path, TrustStore, TrustStoreFilter};
use std::path::{Path, PathBuf};
use std::process::Command;

const FIREFOX_NSS_CERT_NAME: &str = "devssl Local CA";
const JAVA_KEYSTORE_ALIAS: &str = "devssl-local-ca";
const JAVA_KEYSTORE_PASSWORD: &str = "changeit";

pub struct MacOsTrustStore;

impl TrustStore for MacOsTrustStore {
    fn add_ca(&self, cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;

        // Add to system keychain if enabled
        if filter.system {
            let cert_path_str = path_to_str(&safe_cert_path)?;

            // Add to System Keychain (requires admin)
            let output = Command::new("security")
                .args([
                    "add-trusted-cert",
                    "-d", // add to admin cert store
                    "-r",
                    "trustRoot", // trust as root CA
                    "-k",
                    "/Library/Keychains/System.keychain",
                    cert_path_str,
                ])
                .output()
                .map_err(|e| Error::Command {
                    command: "security add-trusted-cert".into(),
                    stderr: e.to_string(),
                })?;

            if !output.status.success() {
                let system_error = String::from_utf8_lossy(&output.stderr);

                // Try user keychain if system keychain fails
                let user_output = Command::new("security")
                    .args([
                        "add-trusted-cert",
                        "-r",
                        "trustRoot",
                        "-k",
                        &get_user_keychain()?,
                        cert_path_str,
                    ])
                    .output()
                    .map_err(|e| Error::Command {
                        command: "security add-trusted-cert".into(),
                        stderr: e.to_string(),
                    })?;

                if !user_output.status.success() {
                    let user_error = String::from_utf8_lossy(&user_output.stderr);
                    return Err(Error::TrustStore(format!(
                        "Failed to add certificate.\nSystem keychain: {}\nUser keychain: {}",
                        system_error.trim(),
                        user_error.trim()
                    )));
                }
            }
        }

        // Add to Firefox NSS databases if enabled (optional, don't fail if it doesn't work)
        if filter.nss {
            add_to_firefox_nss(&safe_cert_path);
        }

        // Add to Java trust store if enabled (optional, don't fail if Java isn't installed)
        if filter.java {
            add_to_java_truststore(&safe_cert_path);
        }

        Ok(())
    }

    fn remove_ca(&self, cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // Remove from system keychain if enabled
        if filter.system {
            let cert_path_str = path_to_str(cert_path)?;

            // Remove by matching certificate
            let output = Command::new("security")
                .args(["remove-trusted-cert", "-d", cert_path_str])
                .output()
                .map_err(|e| Error::Command {
                    command: "security remove-trusted-cert".into(),
                    stderr: e.to_string(),
                })?;

            // Ignore errors - cert might not be installed
            if !output.status.success() {
                // Try to delete from user keychain
                let _ = Command::new("security")
                    .args(["delete-certificate", "-c", CA_COMMON_NAME])
                    .output();
            }
        }

        // Remove from Firefox NSS databases if enabled (optional, don't fail if it doesn't work)
        if filter.nss {
            remove_from_firefox_nss();
        }

        // Remove from Java trust store if enabled (optional, don't fail if Java isn't installed)
        if filter.java {
            remove_from_java_truststore();
        }

        Ok(())
    }

    fn is_trusted(&self, cert_path: &Path) -> Result<bool> {
        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;
        let cert_path_str = path_to_str(&safe_cert_path)?;

        // Check if certificate is trusted
        let output = Command::new("security")
            .args(["verify-cert", "-c", cert_path_str])
            .output()
            .map_err(|e| Error::Command {
                command: "security verify-cert".into(),
                stderr: e.to_string(),
            })?;

        Ok(output.status.success())
    }

    fn name(&self) -> &'static str {
        "macOS Keychain"
    }
}

fn get_user_keychain() -> Result<String> {
    let output = Command::new("security")
        .args(["default-keychain"])
        .output()
        .map_err(|e| Error::Command {
            command: "security default-keychain".into(),
            stderr: e.to_string(),
        })?;

    let keychain = String::from_utf8_lossy(&output.stdout)
        .trim()
        .trim_matches('"')
        .to_string();

    if keychain.is_empty() {
        // Use absolute path for default login keychain
        // Validate HOME to prevent command injection via malicious env var
        if let Some(home) = super::validate_env_path("HOME") {
            Ok(format!(
                "{}/Library/Keychains/login.keychain-db",
                home.display()
            ))
        } else {
            // Fallback to system keychain if HOME is invalid or missing
            Ok("/Library/Keychains/login.keychain-db".into())
        }
    } else {
        Ok(keychain)
    }
}

// ============================================================================
// Firefox NSS Support
// ============================================================================

/// Check if certutil is available on the system.
/// On macOS, certutil is typically installed via Homebrew (nss package).
fn is_certutil_available() -> bool {
    Command::new("which")
        .arg("certutil")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a path is safe to pass to shell commands.
/// Returns true if the path contains no dangerous characters.
fn is_safe_path(path: &Path) -> bool {
    match path.to_str() {
        None => false,
        Some(s) => {
            // Reject paths with shell metacharacters
            const DANGEROUS_CHARS: &[char] = &[
                ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!', '~', '*',
                '?', '#', '\n', '\r', '\0',
            ];
            !DANGEROUS_CHARS.iter().any(|c| s.contains(*c)) && !s.starts_with('-')
        }
    }
}

/// Find Firefox NSS database directories on macOS.
/// Firefox on macOS stores profiles in ~/Library/Application Support/Firefox/Profiles/
fn find_nss_databases() -> Vec<(PathBuf, String)> {
    let mut databases = Vec::new();

    // Get home directory
    let home = match validate_env_path("HOME") {
        Some(h) => h,
        None => return databases,
    };

    // Firefox profile directory on macOS
    let firefox_dir = home
        .join("Library")
        .join("Application Support")
        .join("Firefox")
        .join("Profiles");

    if !firefox_dir.exists() {
        return databases;
    }

    // Find profile directories matching *.default* pattern
    if let Ok(entries) = std::fs::read_dir(&firefox_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Match profiles like "xyz.default", "xyz.default-release", etc.
                    if name.contains(".default") {
                        // Check if it has an NSS database (cert9.db or cert8.db)
                        if path.join("cert9.db").exists() || path.join("cert8.db").exists() {
                            let display_name = format!("Firefox ({})", name);
                            databases.push((path, display_name));
                        }
                    }
                }
            }
        }
    }

    databases
}

/// Add CA certificate to Firefox NSS databases.
/// This is optional - if certutil isn't installed or no databases exist, we silently skip.
fn add_to_firefox_nss(cert_path: &Path) {
    if !is_certutil_available() {
        return;
    }

    let databases = find_nss_databases();
    if databases.is_empty() {
        return;
    }

    // Validate cert_path to prevent command injection
    if !is_safe_path(cert_path) {
        return;
    }

    let cert_path_str = match cert_path.to_str() {
        Some(s) => s,
        None => return,
    };

    for (db_path, display_name) in databases {
        // Validate database path to prevent command injection
        if !is_safe_path(&db_path) {
            continue;
        }

        let db_path_str = match db_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let nss_db = format!("sql:{}", db_path_str);

        // First try to delete any existing cert with the same name (ignore errors)
        let _ = Command::new("certutil")
            .args(["-d", &nss_db, "-D", "-n", FIREFOX_NSS_CERT_NAME])
            .output();

        // Add the certificate
        let output = Command::new("certutil")
            .args([
                "-d",
                &nss_db,
                "-A",
                "-t",
                "C,,",
                "-n",
                FIREFOX_NSS_CERT_NAME,
                "-i",
                cert_path_str,
            ])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                println!("  Added to {}", display_name);
            }
        }
    }
}

/// Remove CA certificate from Firefox NSS databases.
/// This is optional - if certutil isn't installed or no databases exist, we silently skip.
fn remove_from_firefox_nss() {
    if !is_certutil_available() {
        return;
    }

    let databases = find_nss_databases();
    if databases.is_empty() {
        return;
    }

    for (db_path, display_name) in databases {
        // Validate database path to prevent command injection
        if !is_safe_path(&db_path) {
            continue;
        }

        let db_path_str = match db_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let nss_db = format!("sql:{}", db_path_str);

        let output = Command::new("certutil")
            .args(["-d", &nss_db, "-D", "-n", FIREFOX_NSS_CERT_NAME])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                println!("  Removed from {}", display_name);
            }
        }
    }
}

// ============================================================================
// Java Trust Store (cacerts) Support
// ============================================================================

/// Check if keytool is available on the system.
fn is_keytool_available() -> bool {
    Command::new("which")
        .arg("keytool")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find Java trust store (cacerts) location on macOS.
/// Checks $JAVA_HOME/lib/security/cacerts
fn find_java_cacerts() -> Vec<PathBuf> {
    let mut cacerts = Vec::new();

    // Check $JAVA_HOME - use validated path to prevent injection
    if let Some(java_home) = validate_env_path("JAVA_HOME") {
        let path = java_home.join("lib").join("security").join("cacerts");
        if path.exists() {
            // Canonicalize the cacerts path
            if let Ok(canonical) = path.canonicalize() {
                cacerts.push(canonical);
            }
        }
    }

    cacerts
}

/// Add CA certificate to Java trust stores.
/// This is optional - if keytool isn't installed or no cacerts exist, we silently skip.
fn add_to_java_truststore(cert_path: &Path) {
    if !is_keytool_available() {
        return;
    }

    let cacerts = find_java_cacerts();
    if cacerts.is_empty() {
        return;
    }

    // Validate cert_path to prevent command injection
    if !is_safe_path(cert_path) {
        return;
    }

    let cert_path_str = match cert_path.to_str() {
        Some(s) => s,
        None => return,
    };

    for cacert in cacerts {
        // Validate cacert path to prevent command injection
        if !is_safe_path(&cacert) {
            continue;
        }

        let cacert_str = match cacert.to_str() {
            Some(s) => s,
            None => continue,
        };

        // First try to delete any existing cert with the same alias (ignore errors)
        let _ = Command::new("keytool")
            .args([
                "-delete",
                "-keystore",
                cacert_str,
                "-storepass",
                JAVA_KEYSTORE_PASSWORD,
                "-alias",
                JAVA_KEYSTORE_ALIAS,
            ])
            .output();

        // Add the certificate
        let output = Command::new("keytool")
            .args([
                "-import",
                "-trustcacerts",
                "-keystore",
                cacert_str,
                "-storepass",
                JAVA_KEYSTORE_PASSWORD,
                "-noprompt",
                "-alias",
                JAVA_KEYSTORE_ALIAS,
                "-file",
                cert_path_str,
            ])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                println!("  Added to Java trust store: {}", cacert_str);
            }
        }
    }
}

/// Remove CA certificate from Java trust stores.
/// This is optional - if keytool isn't installed or no cacerts exist, we silently skip.
fn remove_from_java_truststore() {
    if !is_keytool_available() {
        return;
    }

    let cacerts = find_java_cacerts();
    if cacerts.is_empty() {
        return;
    }

    for cacert in cacerts {
        // Validate cacert path to prevent command injection
        if !is_safe_path(&cacert) {
            continue;
        }

        let cacert_str = match cacert.to_str() {
            Some(s) => s,
            None => continue,
        };

        let output = Command::new("keytool")
            .args([
                "-delete",
                "-keystore",
                cacert_str,
                "-storepass",
                JAVA_KEYSTORE_PASSWORD,
                "-alias",
                JAVA_KEYSTORE_ALIAS,
            ])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                println!("  Removed from Java trust store: {}", cacert_str);
            }
        }
    }
}

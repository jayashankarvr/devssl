// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::ca::CA_COMMON_NAME;
use crate::error::{Error, Result};
use crate::fs::path_to_str;
use crate::trust::{validate_cert_path, TrustStore, TrustStoreFilter};
use std::path::Path;
use std::process::Command;

pub struct MacOsTrustStore;

impl TrustStore for MacOsTrustStore {
    fn add_ca(&self, cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // On macOS, only the system trust store is supported
        if !filter.system {
            return Ok(());
        }

        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;
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

        Ok(())
    }

    fn remove_ca(&self, cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // On macOS, only the system trust store is supported
        if !filter.system {
            return Ok(());
        }

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

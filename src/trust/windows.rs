// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::ca::CA_COMMON_NAME;
use crate::error::{Error, Result};
use crate::fs::path_to_str;
use crate::trust::{validate_cert_path, TrustStore, TrustStoreFilter};
use std::path::Path;
use std::process::Command;

pub struct WindowsTrustStore;

impl TrustStore for WindowsTrustStore {
    fn add_ca(&self, cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // On Windows, only the system trust store is supported
        if !filter.system {
            return Ok(());
        }

        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;
        let cert_path_str = path_to_str(&safe_cert_path)?;

        // Add certificate to the ROOT store (Trusted Root Certification Authorities)
        let output = Command::new("certutil")
            .args(["-addstore", "-f", "ROOT", cert_path_str])
            .output()
            .map_err(|e| Error::Command {
                command: "certutil -addstore".into(),
                stderr: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(Error::TrustStore(format!(
                "Failed to add certificate to Windows trust store: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn remove_ca(&self, _cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // On Windows, only the system trust store is supported
        if !filter.system {
            return Ok(());
        }

        // Remove certificate from ROOT store by its common name
        let output = Command::new("certutil")
            .args(["-delstore", "ROOT", CA_COMMON_NAME])
            .output()
            .map_err(|e| Error::Command {
                command: "certutil -delstore".into(),
                stderr: e.to_string(),
            })?;

        // Ignore errors - cert might not be installed
        if !output.status.success() {
            // Certificate might not exist, which is fine
        }

        Ok(())
    }

    fn is_trusted(&self, cert_path: &Path) -> Result<bool> {
        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;
        let cert_path_str = path_to_str(&safe_cert_path)?;

        // Use certutil -verify to check if the certificate is trusted
        let output = Command::new("certutil")
            .args(["-verify", cert_path_str])
            .output()
            .map_err(|e| Error::Command {
                command: "certutil -verify".into(),
                stderr: e.to_string(),
            })?;

        Ok(output.status.success())
    }

    fn name(&self) -> &'static str {
        "Windows Certificate Store"
    }
}

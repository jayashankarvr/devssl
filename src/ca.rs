// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::config::Paths;
use crate::error::{Error, Result};
use pkcs8::{EncryptedPrivateKeyInfo, LineEnding, PrivateKeyInfo};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::fs;

pub const CA_COMMON_NAME: &str = "devssl Local CA";
pub const CA_ORG_NAME: &str = "devssl";

/// Local CA for signing development certificates.
pub struct Ca {
    pub key_pair: KeyPair,
    pub cert_pem: String,
}

impl Ca {
    pub fn generate(days: u32) -> Result<Self> {
        crate::cert::validate_days(days)?;
        let key_pair = KeyPair::generate()?;
        let cert = Self::create_ca_cert(&key_pair, days)?;
        let cert_pem = cert.pem();

        Ok(Self { key_pair, cert_pem })
    }

    /// Load CA from unencrypted key file
    pub fn load(paths: &Paths) -> Result<Self> {
        Self::load_with_password(paths, None)
    }

    /// Load CA with optional password for encrypted key
    pub fn load_with_password(paths: &Paths, password: Option<&str>) -> Result<Self> {
        if !paths.ca_exists() {
            return Err(Error::CaNotInitialized);
        }

        let cert_pem = fs::read_to_string(&paths.ca_cert).map_err(|e| Error::ReadFile {
            path: paths.ca_cert.clone(),
            source: e,
        })?;

        // Check if encrypted key exists
        let key_pem = if paths.ca_key_is_encrypted() {
            let password = password.ok_or(Error::PasswordRequired)?;
            decrypt_key_file(&paths.ca_key_enc, password)?
        } else {
            fs::read_to_string(&paths.ca_key).map_err(|e| Error::ReadFile {
                path: paths.ca_key.clone(),
                source: e,
            })?
        };

        let key_pair = KeyPair::from_pem(&key_pem)?;

        Ok(Self { key_pair, cert_pem })
    }

    /// Create an Issuer for signing certificates
    ///
    /// Note: This recreates the KeyPair because Issuer takes ownership
    pub fn issuer(&self) -> Result<Issuer<'_, KeyPair>> {
        let key_pem = self.key_pair.serialize_pem();
        let key_pair = KeyPair::from_pem(&key_pem)?;
        Issuer::from_ca_cert_pem(&self.cert_pem, key_pair).map_err(Error::CertGen)
    }

    fn create_ca_cert(key_pair: &KeyPair, days: u32) -> Result<Certificate> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, CA_COMMON_NAME);
        params
            .distinguished_name
            .push(DnType::OrganizationName, CA_ORG_NAME);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(days as i64);

        Ok(params.self_signed(key_pair)?)
    }

    /// Save CA without encryption
    pub fn save(&self, paths: &Paths) -> Result<()> {
        self.save_with_password(paths, None)
    }

    /// Save CA with optional password for encryption
    pub fn save_with_password(&self, paths: &Paths, password: Option<&str>) -> Result<()> {
        paths.ensure_dir()?;

        if let Some(password) = password {
            // Encrypt and save the key atomically
            let key_pem = self.key_pair.serialize_pem();
            let encrypted_pem = encrypt_key_pem(&key_pem, password)?;
            crate::fs::atomic_write_secret(&paths.ca_key_enc, encrypted_pem.as_bytes())?;

            // Remove unencrypted key if it exists (security: don't leave unencrypted key behind)
            // Use remove directly without exists() check to avoid TOCTOU race
            match fs::remove_file(&paths.ca_key) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Remove {
                        path: paths.ca_key.clone(),
                        source: e,
                    });
                }
            }
        } else {
            // Save unencrypted key atomically
            crate::fs::atomic_write_secret(
                &paths.ca_key,
                self.key_pair.serialize_pem().as_bytes(),
            )?;

            // Remove encrypted key if it exists (cleanup old encrypted key)
            // Use remove directly without exists() check to avoid TOCTOU race
            match fs::remove_file(&paths.ca_key_enc) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Remove {
                        path: paths.ca_key_enc.clone(),
                        source: e,
                    });
                }
            }
        }

        // Save certificate atomically
        crate::fs::atomic_write(&paths.ca_cert, self.cert_pem.as_bytes())?;
        Ok(())
    }

    pub fn days_remaining(&self) -> Result<i64> {
        let info = crate::x509::parse_cert_pem(&self.cert_pem)?;
        Ok(info.days_remaining())
    }
}

/// Encrypt a PEM private key with a password using PKCS#8 with AES-256-CBC
pub fn encrypt_key_pem(key_pem: &str, password: &str) -> Result<String> {
    use pkcs8::der::Decode;
    use rand::RngCore;

    if password.is_empty() {
        return Err(Error::KeyEncryption("Password cannot be empty".to_string()));
    }

    // Parse the PEM to get the DER bytes
    let pem_obj = pem::parse(key_pem)
        .map_err(|e| Error::KeyEncryption(format!("Failed to parse PEM: {}", e)))?;

    // Parse the PrivateKeyInfo from DER
    let pki = PrivateKeyInfo::from_der(pem_obj.contents())
        .map_err(|e| Error::KeyEncryption(format!("Failed to parse key: {}", e)))?;

    // Generate random salt and IV
    let mut rng = rand::rng();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // Encrypt using AES-256-CBC with scrypt
    let encrypted = pki
        .encrypt_with_params(
            pkcs8::pkcs5::pbes2::Parameters::scrypt_aes256cbc(
                pkcs8::pkcs5::scrypt::Params::recommended(),
                &salt,
                &iv,
            )
            .map_err(|e| {
                Error::KeyEncryption(format!("Failed to create encryption params: {}", e))
            })?,
            password,
        )
        .map_err(|e| Error::KeyEncryption(format!("Encryption failed: {}", e)))?;

    // Convert to PEM
    let pem_str = encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .map_err(|e| Error::KeyEncryption(format!("Failed to convert to PEM: {}", e)))?;

    Ok(pem_str.to_string())
}

/// Decrypt a PEM encrypted private key with a password
pub fn decrypt_key_pem(encrypted_pem: &str, password: &str) -> Result<String> {
    use pkcs8::der::Decode;

    if password.is_empty() {
        return Err(Error::KeyDecryption("Password cannot be empty".to_string()));
    }

    // Parse the encrypted PEM
    let pem_obj = pem::parse(encrypted_pem)
        .map_err(|e| Error::KeyDecryption(format!("Failed to parse encrypted PEM: {}", e)))?;

    // Parse the EncryptedPrivateKeyInfo
    let encrypted = EncryptedPrivateKeyInfo::from_der(pem_obj.contents())
        .map_err(|e| Error::KeyDecryption(format!("Failed to parse encrypted key: {}", e)))?;

    // Decrypt the key
    let decrypted = encrypted
        .decrypt(password)
        .map_err(|_| Error::PasswordIncorrect)?;

    // Convert back to PEM
    let pem_str = decrypted
        .to_pem("PRIVATE KEY", LineEnding::LF)
        .map_err(|e| Error::KeyDecryption(format!("Failed to convert to PEM: {}", e)))?;

    Ok(pem_str.to_string())
}

/// Decrypt an encrypted key file with a password
pub fn decrypt_key_file(path: &std::path::Path, password: &str) -> Result<String> {
    let encrypted_pem = fs::read_to_string(path).map_err(|e| Error::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    decrypt_key_pem(&encrypted_pem, password)
}

/// Encrypt an existing CA key file
pub fn encrypt_existing_key(paths: &Paths, password: &str) -> Result<()> {
    if !paths.ca_key.exists() {
        return Err(Error::CaNotInitialized);
    }

    // Read the unencrypted key
    let key_pem = fs::read_to_string(&paths.ca_key).map_err(|e| Error::ReadFile {
        path: paths.ca_key.clone(),
        source: e,
    })?;

    // Encrypt it
    let encrypted_pem = encrypt_key_pem(&key_pem, password)?;

    // Write the encrypted key
    crate::fs::write_secret_file(&paths.ca_key_enc, encrypted_pem.as_bytes())?;

    // Remove the unencrypted key
    // If this fails, we must clean up the encrypted key to avoid having both
    if let Err(e) = fs::remove_file(&paths.ca_key) {
        // Try to clean up the encrypted key we just wrote
        let _ = fs::remove_file(&paths.ca_key_enc);
        return Err(Error::Remove {
            path: paths.ca_key.clone(),
            source: e,
        });
    }

    Ok(())
}

/// Decrypt an encrypted CA key file (removes encryption)
pub fn decrypt_existing_key(paths: &Paths, password: &str) -> Result<()> {
    if !paths.ca_key_enc.exists() {
        return Err(Error::NoEncryptedKey(paths.ca_key_enc.clone()));
    }

    // Decrypt the key
    let key_pem = decrypt_key_file(&paths.ca_key_enc, password)?;

    // Write the unencrypted key
    crate::fs::write_secret_file(&paths.ca_key, key_pem.as_bytes())?;

    // Remove the encrypted key
    // If this fails, we must clean up the unencrypted key to avoid having both
    if let Err(e) = fs::remove_file(&paths.ca_key_enc) {
        // Try to clean up the unencrypted key we just wrote
        let _ = fs::remove_file(&paths.ca_key);
        return Err(Error::Remove {
            path: paths.ca_key_enc.clone(),
            source: e,
        });
    }

    Ok(())
}

/// Change the password on an encrypted CA key
pub fn change_key_password(paths: &Paths, old_password: &str, new_password: &str) -> Result<()> {
    if !paths.ca_key_enc.exists() {
        return Err(Error::NoEncryptedKey(paths.ca_key_enc.clone()));
    }

    // Decrypt with old password
    let key_pem = decrypt_key_file(&paths.ca_key_enc, old_password)?;

    // Re-encrypt with new password
    let encrypted_pem = encrypt_key_pem(&key_pem, new_password)?;

    // Write the new encrypted key
    crate::fs::write_secret_file(&paths.ca_key_enc, encrypted_pem.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generate() {
        let ca = Ca::generate(30).unwrap();

        assert!(!ca.key_pair.serialize_pem().is_empty());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_ca_generate_invalid_days() {
        assert!(Ca::generate(0).is_err());
        assert!(Ca::generate(3651).is_err());
    }

    #[test]
    fn test_ca_cert_pem() {
        let ca = Ca::generate(30).unwrap();

        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_ca_days_remaining() {
        let ca = Ca::generate(30).unwrap();
        let days = ca.days_remaining().unwrap();

        assert!(days >= 29);
        assert!(days <= 30);
    }
}

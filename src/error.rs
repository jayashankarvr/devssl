// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CA not initialized. Run 'devssl init' first.")]
    CaNotInitialized,

    #[error("CA already exists at {0}. Use --force to regenerate.")]
    CaAlreadyExists(PathBuf),

    #[error("Failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to remove {path}: {source}")]
    Remove {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to read file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to read directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to write file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Certificate generation failed: {0}")]
    CertGen(#[from] rcgen::Error),

    #[error("Invalid domain '{domain}': {reason}")]
    InvalidDomain { domain: String, reason: String },

    #[error("Invalid validity period: {0}")]
    InvalidDays(String),

    #[error("No domains specified")]
    NoDomains,

    #[error("Invalid email address '{email}': {reason}")]
    InvalidEmail { email: String, reason: String },

    #[error("'{0}' is a reserved name and cannot be used for certificates")]
    ReservedName(String),

    #[error("Invalid path (non-UTF8): {0}")]
    InvalidPath(std::path::PathBuf),

    #[error("Trust store operation failed: {0}")]
    TrustStore(String),

    #[error("Trust store operation timed out after {seconds} seconds.\nThe sudo prompt may have been ignored or the operation is hanging.\nTry running: sudo devssl init")]
    TrustStoreTimeout { seconds: u64 },

    #[error("Sudo authentication failed or was cancelled.\nTrust store installation requires elevated privileges.\nRun: sudo devssl init")]
    SudoFailed,

    #[error("Command '{command}' not found.\n{hint}")]
    CommandNotFound { command: String, hint: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Certificate '{name}' not found. Run 'devssl generate {name}' first.")]
    CertificateNotFound { name: String },

    #[error("Failed to bind to {addr}: {reason}\nIs another process using this port?")]
    BindFailed { addr: String, reason: String },

    #[error("Invalid port '{port}': must be a number between 1 and 65535")]
    InvalidPort { port: String },

    #[error("Command failed: {command}\n{stderr}")]
    Command { command: String, stderr: String },

    #[error("Failed to parse certificate: {0}")]
    CertParse(String),

    #[error("Failed to parse CSR: {0}")]
    CsrParse(String),

    #[error("Failed to export PKCS12: {0}")]
    Pkcs12Export(String),

    #[error("Password required to decrypt CA key")]
    PasswordRequired,

    #[error("Incorrect password or corrupted encrypted key")]
    PasswordIncorrect,

    #[error("Key encryption failed: {0}")]
    KeyEncryption(String),

    #[error("Key decryption failed: {0}")]
    KeyDecryption(String),

    #[error("No encrypted CA key found at {0}")]
    NoEncryptedKey(std::path::PathBuf),

    #[error("CA key is not encrypted")]
    KeyNotEncrypted,
}

pub type Result<T> = std::result::Result<T, Error>;

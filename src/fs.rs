// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use std::path::Path;

pub fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))
}

/// Atomically write data to a file using a temporary file and rename.
/// This prevents race conditions where a file is read while being written.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs;
    use std::io::Write;

    // Create temp file in same directory to ensure same filesystem (required for atomic rename)
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))?;

    // Generate random temp filename
    let random_suffix: u64 = rand::Rng::random(&mut rand::rng());
    let temp_path = parent.join(format!(".tmp-{:x}", random_suffix));

    // Write to temp file
    let mut file = fs::File::create(&temp_path).map_err(|e| Error::WriteFile {
        path: temp_path.clone(),
        source: e,
    })?;

    file.write_all(contents).map_err(|e| Error::WriteFile {
        path: temp_path.clone(),
        source: e,
    })?;

    // Ensure data is flushed to disk before rename
    file.sync_all().map_err(|e| Error::WriteFile {
        path: temp_path.clone(),
        source: e,
    })?;

    drop(file); // Close file before rename

    // Atomic rename (overwrites destination atomically)
    fs::rename(&temp_path, path).map_err(|e| {
        // Clean up temp file on error - but only if it still exists
        if temp_path.exists() {
            let _ = fs::remove_file(&temp_path);
        }
        Error::WriteFile {
            path: path.to_path_buf(),
            source: e,
        }
    })?;

    Ok(())
}

/// Atomically write secret file with proper permissions using temp file and rename.
/// This prevents race conditions where a file is read while being written.
pub fn atomic_write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs;

    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))?;
    let random_suffix: u64 = rand::Rng::random(&mut rand::rng());
    let temp_path = parent.join(format!(".tmp-{:x}", random_suffix));

    // Write to temp file with secure permissions
    write_secret_file(&temp_path, contents)?;

    // Atomic rename
    fs::rename(&temp_path, path).map_err(|e| {
        // Clean up temp file on error - but only if it still exists
        if temp_path.exists() {
            let _ = fs::remove_file(&temp_path);
        }
        Error::WriteFile {
            path: path.to_path_buf(),
            source: e,
        }
    })?;

    Ok(())
}

#[cfg(unix)]
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::WriteFile {
            path: path.to_path_buf(),
            source: e,
        })?;

    file.write_all(contents).map_err(|e| Error::WriteFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

#[cfg(windows)]
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::process::Command;

    std::fs::write(path, contents).map_err(|e| Error::WriteFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Restrict to current user only via icacls - MUST succeed for security
    let path_str = path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))?;

    // Try multiple methods to get username
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USERDOMAIN_ROAMINGPROFILE"))
        .or_else(|_| {
            // Fallback to whoami command
            Command::new("whoami")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .ok_or(std::env::VarError::NotPresent)
        })
        .map_err(|_| {
            Error::Config("Cannot determine current user for file permissions".to_string())
        })?;

    let output = Command::new("icacls")
        .args([
            path_str,
            "/inheritance:r",
            "/grant:r",
            &format!("{}:F", username),
        ])
        .output()
        .map_err(|e| Error::Config(format!("Failed to run icacls: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Delete the file to avoid leaving world-readable private key
        if let Err(e) = std::fs::remove_file(path) {
            eprintln!("Warning: Failed to remove insecure key file: {}", e);
            eprintln!("         Please manually delete: {}", path.display());
        }

        return Err(Error::Config(format!(
            "Failed to set file permissions: {}\n\
             Key file not saved for security.\n\
             icacls error: {}",
            path.display(),
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).map_err(|e| Error::WriteFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Names reserved for devssl internal use (cannot be used as certificate names).
pub const RESERVED_NAMES: &[&str] = &[
    "ca", "config", "daemon", "chain", "backup", "restore", "trust", "list", "inspect",
];

pub fn is_reserved_name(name: &str) -> bool {
    RESERVED_NAMES.contains(&name.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserved_names() {
        // Original reserved names
        assert!(is_reserved_name("ca"));
        assert!(is_reserved_name("CA"));
        assert!(is_reserved_name("Ca"));
        assert!(is_reserved_name("config"));
        assert!(is_reserved_name("CONFIG"));
        assert!(is_reserved_name("daemon"));
        assert!(is_reserved_name("DAEMON"));
        assert!(is_reserved_name("Daemon"));

        // New command names
        assert!(is_reserved_name("chain"));
        assert!(is_reserved_name("backup"));
        assert!(is_reserved_name("restore"));
        assert!(is_reserved_name("trust"));
        assert!(is_reserved_name("list"));
        assert!(is_reserved_name("inspect"));

        // Valid names
        assert!(!is_reserved_name("localhost"));
        assert!(!is_reserved_name("myapp"));
        assert!(!is_reserved_name("myapp.local"));
    }
}

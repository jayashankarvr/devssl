// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::fs::path_to_str;
use crate::trust::{validate_cert_path, validate_env_path, TrustStore, TrustStoreFilter};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Default timeout for sudo operations (30 seconds)
const SUDO_TIMEOUT_SECS: u64 = 30;

const TRUST_STORE_CERT_NAME: &str = "devssl-local-ca.crt";
const FIREFOX_NSS_CERT_NAME: &str = "devssl Local CA";
const JAVA_KEYSTORE_ALIAS: &str = "devssl-local-ca";
const JAVA_KEYSTORE_PASSWORD: &str = "changeit";

pub struct LinuxTrustStore {
    distro: LinuxDistro,
}

#[derive(Debug, Clone, Copy)]
enum LinuxDistro {
    Debian, // Ubuntu, Mint, Pop!_OS, etc.
    Fedora, // RHEL, CentOS, Rocky, Alma
    Arch,   // Manjaro, EndeavourOS
    Unknown,
}

impl LinuxDistro {
    fn trust_store_dir(&self) -> Option<&'static Path> {
        match self {
            LinuxDistro::Debian => Some(Path::new("/usr/local/share/ca-certificates")),
            LinuxDistro::Fedora => Some(Path::new("/etc/pki/ca-trust/source/anchors")),
            LinuxDistro::Arch => Some(Path::new("/etc/ca-certificates/trust-source/anchors")),
            LinuxDistro::Unknown => None,
        }
    }

    fn cert_path(&self) -> Option<PathBuf> {
        self.trust_store_dir()
            .map(|dir| dir.join(TRUST_STORE_CERT_NAME))
    }

    fn update_command(&self) -> Option<&'static [&'static str]> {
        match self {
            LinuxDistro::Debian => Some(&["update-ca-certificates"]),
            LinuxDistro::Fedora => Some(&["update-ca-trust", "extract"]),
            LinuxDistro::Arch => Some(&["trust", "extract-compat"]),
            LinuxDistro::Unknown => None,
        }
    }
}

impl LinuxTrustStore {
    pub fn detect() -> Self {
        Self {
            distro: detect_distro(),
        }
    }
}

impl TrustStore for LinuxTrustStore {
    fn add_ca(&self, cert_path: &Path) -> Result<()> {
        // Validate path to prevent command injection
        let safe_cert_path = validate_cert_path(cert_path)?;

        let filter = TrustStoreFilter::from_env();

        // Add to system trust store if enabled
        if filter.system {
            let dest = self.distro.cert_path().ok_or_else(|| {
                Error::TrustStore(
                    "Unknown Linux distribution. Please manually install the CA certificate."
                        .into(),
                )
            })?;

            let update_cmd = self.distro.update_command().ok_or_else(|| {
                Error::TrustStore("No update command available for this distribution.".into())
            })?;

            copy_with_sudo(&safe_cert_path, &dest)?;
            run_update_command(update_cmd)?;
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

    fn remove_ca(&self, _cert_path: &Path) -> Result<()> {
        let filter = TrustStoreFilter::from_env();

        // Remove from system trust store if enabled
        if filter.system {
            if let Some(dest) = self.distro.cert_path() {
                // Remove the certificate file directly (avoid TOCTOU with exists() check)
                // The remove_with_sudo function will handle non-existent files gracefully
                let _ = remove_with_sudo(&dest);

                // Update trust store
                if let Some(update_cmd) = self.distro.update_command() {
                    let _ = run_update_command(update_cmd);
                }
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
        // Check if our CA certificate exists in the trust store directory
        // AND verify it matches the provided certificate
        let trust_store_path = match self.distro.cert_path() {
            Some(path) => path,
            None => return Ok(false),
        };

        if !trust_store_path.exists() {
            return Ok(false);
        }

        // Read both certificates and compare content
        let trusted_content = match std::fs::read_to_string(&trust_store_path) {
            Ok(content) => content,
            Err(_) => return Ok(false),
        };

        let our_content = std::fs::read_to_string(cert_path).map_err(|e| Error::ReadFile {
            path: cert_path.to_path_buf(),
            source: e,
        })?;

        // Normalize PEM content for comparison (remove whitespace variations)
        let normalize = |s: &str| s.lines().collect::<Vec<_>>().join("\n");

        Ok(normalize(&trusted_content) == normalize(&our_content))
    }

    fn name(&self) -> &'static str {
        match self.distro {
            LinuxDistro::Debian => "Debian/Ubuntu ca-certificates",
            LinuxDistro::Fedora => "Fedora/RHEL ca-trust",
            LinuxDistro::Arch => "Arch trust",
            LinuxDistro::Unknown => "Linux (unknown)",
        }
    }
}

fn detect_distro() -> LinuxDistro {
    // Check for os-release file
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let content = content.to_lowercase();

        if content.contains("debian")
            || content.contains("ubuntu")
            || content.contains("mint")
            || content.contains("pop!_os")
        {
            return LinuxDistro::Debian;
        }

        if content.contains("fedora")
            || content.contains("rhel")
            || content.contains("centos")
            || content.contains("rocky")
            || content.contains("alma")
        {
            return LinuxDistro::Fedora;
        }

        if content.contains("arch") || content.contains("manjaro") || content.contains("endeavour")
        {
            return LinuxDistro::Arch;
        }
    }

    // Fallback: check for update commands
    if Path::new("/usr/sbin/update-ca-certificates").exists() {
        return LinuxDistro::Debian;
    }
    if Path::new("/usr/bin/update-ca-trust").exists() {
        return LinuxDistro::Fedora;
    }
    if Path::new("/usr/bin/trust").exists() {
        return LinuxDistro::Arch;
    }

    LinuxDistro::Unknown
}

/// Run a command with a timeout. Returns the command output or an error.
fn run_command_with_timeout(
    command: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<std::process::Output> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit()) // Allow sudo to prompt for password
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::CommandNotFound {
                    command: command.to_string(),
                    hint: get_install_hint(command),
                }
            } else {
                Error::Command {
                    command: command.to_string(),
                    stderr: e.to_string(),
                }
            }
        })?;

    let timeout = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process finished
                return child.wait_with_output().map_err(|e| Error::Command {
                    command: command.to_string(),
                    stderr: e.to_string(),
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() >= timeout {
                    // Kill the process on timeout and wait to reap it (prevent zombies)
                    let _ = child.kill();
                    let _ = child.wait(); // Reap the child process
                    return Err(Error::TrustStoreTimeout {
                        seconds: timeout_secs,
                    });
                }
                // Sleep briefly before checking again
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(Error::Command {
                    command: command.to_string(),
                    stderr: e.to_string(),
                });
            }
        }
    }
}

/// Get installation hint for missing commands
fn get_install_hint(command: &str) -> String {
    match command {
        "sudo" => {
            "Sudo is required for trust store operations. Please install sudo or run as root."
                .to_string()
        }
        "update-ca-certificates" => {
            "Install ca-certificates package: sudo apt install ca-certificates".to_string()
        }
        "update-ca-trust" => {
            "Install ca-certificates package: sudo dnf install ca-certificates".to_string()
        }
        "trust" => "Install p11-kit-trust package: sudo pacman -S p11-kit".to_string(),
        "certutil" => {
            "Optional: Install certutil for Firefox support: sudo apt install libnss3-tools"
                .to_string()
        }
        "keytool" => "Optional: Install Java JDK for Java application support".to_string(),
        _ => format!("Please install the '{}' command", command),
    }
}

/// Check if sudo error indicates authentication failure
fn is_sudo_auth_failure(stderr: &str) -> bool {
    stderr.contains("sudo: no password was provided")
        || stderr.contains("sudo: a password is required")
        || stderr.contains("Sorry, try again")
        || stderr.contains("sudo: 3 incorrect password attempts")
        || stderr.contains("Authentication failure")
        || stderr.contains("Permission denied")
}

fn copy_with_sudo(src: &Path, dest: &Path) -> Result<()> {
    let src_str = path_to_str(src)?;
    let dest_str = path_to_str(dest)?;

    let output = run_command_with_timeout("sudo", &["cp", src_str, dest_str], SUDO_TIMEOUT_SECS)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_sudo_auth_failure(&stderr) {
            return Err(Error::SudoFailed);
        }
        return Err(Error::TrustStore(format!(
            "Failed to copy certificate to trust store: {}\nTry running: sudo devssl init",
            stderr.trim()
        )));
    }

    Ok(())
}

fn remove_with_sudo(path: &Path) -> Result<()> {
    let path_str = path_to_str(path)?;

    let output = run_command_with_timeout("sudo", &["rm", "-f", path_str], SUDO_TIMEOUT_SECS)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_sudo_auth_failure(&stderr) {
            return Err(Error::SudoFailed);
        }
        return Err(Error::TrustStore(format!(
            "Failed to remove certificate from trust store: {}\nTry running: sudo devssl clean",
            stderr.trim()
        )));
    }

    Ok(())
}

fn run_update_command(args: &[&str]) -> Result<()> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| Error::TrustStore("No command provided".into()))?;

    // Build args for sudo: ["cmd", rest...]
    let mut sudo_args = vec![*cmd];
    sudo_args.extend(rest.iter().copied());

    let output = run_command_with_timeout("sudo", &sudo_args, SUDO_TIMEOUT_SECS)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_sudo_auth_failure(&stderr) {
            return Err(Error::SudoFailed);
        }

        // Check if the command itself was not found
        if stderr.contains("not found") || stderr.contains("No such file") {
            return Err(Error::CommandNotFound {
                command: cmd.to_string(),
                hint: get_install_hint(cmd),
            });
        }

        return Err(Error::TrustStore(format!(
            "Failed to update trust store: {}\nTry running: sudo devssl init",
            stderr.trim()
        )));
    }

    Ok(())
}

// ============================================================================
// Firefox NSS Support
// ============================================================================

/// Check if certutil is available on the system.
/// certutil is provided by libnss3-tools (Debian/Ubuntu) or nss-tools (Fedora/RHEL).
fn is_certutil_available() -> bool {
    Command::new("which")
        .arg("certutil")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find NSS database directories for browsers (Chrome, Chromium, Firefox).
/// Get the real user's home directory, even when running with sudo.
/// When running with sudo, HOME is /root but SUDO_USER contains the original username.
fn get_real_user_home() -> Option<PathBuf> {
    // First check if we're running with sudo
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        // Validate the username to prevent injection
        if sudo_user
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            let home = PathBuf::from("/home").join(&sudo_user);
            if home.exists() && home.is_dir() {
                return Some(home);
            }
        }
    }

    // Fall back to HOME environment variable
    validate_env_path("HOME")
}

/// Looks in multiple locations:
/// - ~/.pki/nssdb/ (Chrome/Chromium)
/// - ~/.mozilla/firefox/ (native Firefox)
/// - ~/snap/firefox/common/.mozilla/firefox/ (Snap Firefox)
/// - ~/.var/app/org.mozilla.firefox/.mozilla/firefox/ (Flatpak Firefox)
fn find_nss_databases() -> Vec<(PathBuf, String)> {
    let mut databases = Vec::new();

    // Get home directory - detect real user even when running with sudo
    let home = match get_real_user_home() {
        Some(h) => h,
        None => return databases,
    };

    // Chrome/Chromium NSS database
    let chrome_nss = home.join(".pki").join("nssdb");
    if chrome_nss.exists() && chrome_nss.join("cert9.db").exists() {
        databases.push((chrome_nss, "Chrome/Chromium".to_string()));
    }

    // Firefox profile directories to search
    let firefox_dirs = [
        // Native Firefox
        home.join(".mozilla").join("firefox"),
        // Snap Firefox
        home.join("snap")
            .join("firefox")
            .join("common")
            .join(".mozilla")
            .join("firefox"),
        // Flatpak Firefox
        home.join(".var")
            .join("app")
            .join("org.mozilla.firefox")
            .join(".mozilla")
            .join("firefox"),
    ];

    for firefox_dir in &firefox_dirs {
        if !firefox_dir.exists() {
            continue;
        }

        // Find profile directories matching *.default* pattern
        if let Ok(entries) = std::fs::read_dir(firefox_dir) {
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
    }

    databases
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

/// Add CA certificate to all browser NSS databases (Chrome, Firefox).
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

/// Remove CA certificate from all browser NSS databases (Chrome, Firefox).
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

/// Find Java trust store (cacerts) locations.
/// Checks:
/// - $JAVA_HOME/lib/security/cacerts (standard location)
/// - /etc/ssl/certs/java/cacerts (Debian/Ubuntu)
/// - /etc/pki/java/cacerts (Fedora/RHEL)
fn find_java_cacerts() -> Vec<PathBuf> {
    let mut cacerts = Vec::new();

    // Check $JAVA_HOME first - use validated path to prevent injection
    if let Some(java_home) = validate_env_path("JAVA_HOME") {
        let path = java_home.join("lib").join("security").join("cacerts");
        if path.exists() {
            // Canonicalize the cacerts path too
            if let Ok(canonical) = path.canonicalize() {
                cacerts.push(canonical);
            }
        }
    }

    // Check system-wide locations
    let system_paths = [
        "/etc/ssl/certs/java/cacerts", // Debian/Ubuntu
        "/etc/pki/java/cacerts",       // Fedora/RHEL
    ];

    for path_str in &system_paths {
        let path = PathBuf::from(path_str);
        if path.exists() {
            // Canonicalize to get the real path
            if let Ok(canonical) = path.canonicalize() {
                if !cacerts.contains(&canonical) {
                    cacerts.push(canonical);
                }
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
        let _ = Command::new("sudo")
            .args([
                "keytool",
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
        let output = Command::new("sudo")
            .args([
                "keytool",
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

        let output = Command::new("sudo")
            .args([
                "keytool",
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

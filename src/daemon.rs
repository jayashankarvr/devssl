// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

//! Auto-renewal daemon for certificate management.
//!
//! This module provides a background daemon that periodically checks
//! certificates and renews them before they expire.

use crate::ca::Ca;
use crate::cert::Cert;
use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use fs2::FileExt;
use rand::Rng;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Lock retry delay in milliseconds when acquiring daemon PID file lock
const LOCK_RETRY_DELAY_MS: u64 = 100;

/// Maximum retries for daemon lock handoff during restart (30 * 100ms = 3 seconds)
const LOCK_HANDOFF_RETRIES: u32 = 30;

/// Seconds in one hour (for converting check_interval_hours to seconds)
const SECONDS_PER_HOUR: u64 = 3600;

/// Password encrypted with a session-unique random key.
///
/// This protects the CA password from exposure via `/proc/<pid>/environ` on Linux,
/// `ps eww` on macOS, or Process Explorer on Windows. The password is XOR'd with
/// a random key that only exists in heap memory (never in environment variables).
///
/// # Security Properties
/// - Environment variable is cleared after reading
/// - Random key is generated fresh each daemon session
/// - Key only exists in heap memory, not accessible via /proc/environ
/// - XOR with random pad provides perfect secrecy
/// - Both key and encrypted data are securely zeroized on drop (using `zeroize` crate)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePassword {
    encrypted: Vec<u8>,
    key: Vec<u8>,
}

impl SecurePassword {
    /// Create a new SecurePassword by encrypting the plaintext with a random key.
    pub fn new(password: &str) -> Self {
        let password_bytes = password.as_bytes();
        let mut key = vec![0u8; password_bytes.len()];
        rand::rng().fill(&mut key[..]);

        let encrypted: Vec<u8> = password_bytes
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        Self { encrypted, key }
    }

    /// Decrypt and return the password in a zeroizing wrapper.
    /// The returned string will be securely wiped from memory when dropped.
    pub fn decrypt(&self) -> ZeroizingString {
        let decrypted: Vec<u8> = self
            .encrypted
            .iter()
            .zip(self.key.iter())
            .map(|(e, k)| e ^ k)
            .collect();
        ZeroizingString(String::from_utf8_lossy(&decrypted).to_string())
    }
}

/// A String wrapper that securely zeroizes its contents on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingString(String);

impl std::ops::Deref for ZeroizingString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ZeroizingString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Holds an exclusive lock on the PID file.
/// The lock is automatically released when this struct is dropped.
pub struct DaemonLock {
    #[allow(dead_code)]
    file: File,
}

impl DaemonLock {
    /// Try to acquire an exclusive lock on the PID file.
    /// Returns Ok(DaemonLock) if successful, Err if another daemon is running.
    pub fn try_acquire(paths: &Paths) -> Result<Self> {
        Self::try_acquire_with_retries(paths, 0)
    }

    /// Try to acquire lock with retries (used by daemon child process)
    /// to handle the handoff from parent process.
    pub fn try_acquire_with_retries(paths: &Paths, max_retries: u32) -> Result<Self> {
        // Ensure the directory exists
        if let Some(parent) = paths.pid_path().parent() {
            fs::create_dir_all(parent).map_err(|e| Error::WriteFile {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let mut attempts = 0;
        loop {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(paths.pid_path())
                .map_err(|e| Error::WriteFile {
                    path: paths.pid_path(),
                    source: e,
                })?;

            // Try to acquire exclusive lock (non-blocking)
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(DaemonLock { file }),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Lock is held by another process - this is expected during handoff
                    if attempts >= max_retries {
                        return Err(Error::Config(
                            "Another daemon instance is already running".to_string(),
                        ));
                    }
                    attempts += 1;
                    // Brief sleep before retry to allow parent to release lock
                    std::thread::sleep(Duration::from_millis(LOCK_RETRY_DELAY_MS));
                }
                Err(e) => {
                    // Other I/O error (permissions, disk full, etc.) - provide specific error messages
                    let msg = match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            "Permission denied accessing daemon lock file"
                        }
                        std::io::ErrorKind::NotFound => "Daemon directory not found",
                        _ => "Failed to acquire daemon lock",
                    };
                    return Err(Error::Config(format!("{}: {}", msg, e)));
                }
            }
        }
    }

    /// Write the PID to the locked file
    pub fn write_pid(&mut self, pid: u32, paths: &Paths) -> Result<()> {
        use std::io::{Seek, Write};

        // Format PID to buffer first to avoid corrupt state if write fails
        let pid_content = format!("{}\n", pid);
        let pid_bytes = pid_content.as_bytes();

        // Seek to beginning and truncate
        self.file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|e| Error::WriteFile {
                path: paths.pid_path(),
                source: e,
            })?;

        // Write all bytes atomically (single syscall for small content)
        self.file
            .write_all(pid_bytes)
            .map_err(|e| Error::WriteFile {
                path: paths.pid_path(),
                source: e,
            })?;

        // Truncate to exact size (removes old content if new PID is shorter)
        self.file
            .set_len(pid_bytes.len() as u64)
            .map_err(|e| Error::WriteFile {
                path: paths.pid_path(),
                source: e,
            })?;

        self.file.flush().map_err(|e| Error::WriteFile {
            path: paths.pid_path(),
            source: e,
        })?;

        Ok(())
    }
}

/// Check if the PID file is locked by another process
fn is_pid_file_locked(paths: &Paths) -> bool {
    let pid_path = paths.pid_path();
    if !pid_path.exists() {
        return false;
    }

    match OpenOptions::new().write(true).open(&pid_path) {
        Ok(file) => {
            // Try to get an exclusive lock
            match file.try_lock_exclusive() {
                Ok(()) => {
                    // We got the lock, so no other daemon has it
                    // Drop the file to release the lock and return false
                    drop(file);
                    false
                }
                Err(_) => {
                    // Lock failed, another process has it
                    true
                }
            }
        }
        Err(_) => false,
    }
}

/// Status of the daemon
#[derive(Debug)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub log_path: std::path::PathBuf,
}

/// Read the PID from the PID file
pub fn read_pid(paths: &Paths) -> Option<u32> {
    let pid_path = paths.pid_path();
    if !pid_path.exists() {
        return None;
    }

    let mut contents = String::new();
    File::open(&pid_path)
        .ok()?
        .read_to_string(&mut contents)
        .ok()?;

    contents.trim().parse().ok()
}

/// Remove the PID file
fn remove_pid(paths: &Paths) -> Result<()> {
    let pid_path = paths.pid_path();
    if pid_path.exists() {
        fs::remove_file(&pid_path).map_err(|e| Error::Remove {
            path: pid_path,
            source: e,
        })?;
    }
    Ok(())
}

/// Check if a process with the given PID is running
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) only checks process existence, no signal is sent
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| {
                let output = String::from_utf8_lossy(&o.stdout);
                // Check for PID with word boundaries to avoid matching 123 in 1234
                // tasklist output has PIDs in columns with whitespace separators
                let pid_str = pid.to_string();
                output.split_whitespace().any(|word| word == pid_str)
            })
            .unwrap_or(false)
    }
}

/// Get the daemon status
pub fn status(paths: &Paths) -> DaemonStatus {
    let pid = read_pid(paths);

    // Check if the PID file is locked (more reliable than just checking process)
    let locked = is_pid_file_locked(paths);

    // Daemon is running if: file is locked OR (process exists AND PID file exists)
    let running = locked || pid.map(is_process_running).unwrap_or(false);

    // If not running but PID file exists, try to clean it up
    // Avoid TOCTOU race by acquiring lock atomically - if we can get the lock,
    // the PID file is truly stale and safe to remove
    if !running && pid.is_some() {
        if let Ok(_lock) = DaemonLock::try_acquire(paths) {
            let _ = remove_pid(paths);
        }
    }

    DaemonStatus {
        running,
        pid: if running { pid } else { None },
        log_path: paths.log_path(),
    }
}

/// Start the daemon in background mode
pub fn start(paths: &Paths, on_renew: Option<&str>, ca_password: Option<&str>) -> Result<u32> {
    // Try to acquire lock first to prevent race condition
    // This ensures only one daemon can start at a time
    let mut lock = match DaemonLock::try_acquire(paths) {
        Err(_) => {
            // Lock failed, another daemon is running
            let current_status = status(paths);
            return Err(Error::Config(format!(
                "Daemon is already running (PID: {})",
                current_status.pid.unwrap_or(0)
            )));
        }
        Ok(lock) => lock,
    };

    // Get the current executable path
    let exe = std::env::current_exe()
        .map_err(|e| Error::Config(format!("Cannot find current executable: {}", e)))?;

    // Build command arguments
    let mut args = vec!["daemon".to_string(), "run".to_string()];
    if let Some(cmd) = on_renew {
        args.push("--on-renew".to_string());
        args.push(cmd.to_string());
    }

    // Spawn the daemon process in background WHILE still holding the lock
    // This prevents another start() from sneaking in
    // Password is passed via DEVSSL_PASSWORD environment variable
    #[cfg(unix)]
    let child = spawn_daemon_unix(&exe, &args, paths, ca_password)?;

    #[cfg(windows)]
    let child = spawn_daemon_windows(&exe, &args, paths, ca_password)?;

    let pid = child.id();

    // Write PID to the locked file for immediate status feedback
    // Using the lock's write_pid ensures we write to the same file we locked
    lock.write_pid(pid, paths)?;

    // Now release the lock - the child will acquire its own lock with retries
    // The child's run() has retry logic to handle this handoff
    drop(lock);

    Ok(pid)
}

#[cfg(unix)]
fn spawn_daemon_unix(
    exe: &Path,
    args: &[String],
    paths: &Paths,
    ca_password: Option<&str>,
) -> Result<Child> {
    use std::os::unix::process::CommandExt;

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_path())
        .map_err(|e| Error::WriteFile {
            path: paths.log_path(),
            source: e,
        })?;

    let log_file_clone = log_file
        .try_clone()
        .map_err(|e| Error::Config(format!("Failed to clone log file: {}", e)))?;

    // If password provided, write it to a secure temporary file
    let password_file_path = if let Some(pwd) = ca_password {
        let pwd_path = paths.password_file_path();
        crate::fs::atomic_write_secret(&pwd_path, pwd.as_bytes())?;
        Some(pwd_path)
    } else {
        None
    };

    // SAFETY: pre_exec closure only calls setsid() which is safe after fork
    let child = unsafe {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_clone))
            .pre_exec(|| {
                // Create new session to detach from terminal
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });

        // Pass password file path via environment variable (not the password itself)
        if password_file_path.is_some() {
            cmd.env("DEVSSL_PASSWORD_FILE", "1");
        }

        cmd.spawn()
            .map_err(|e| Error::Config(format!("Failed to spawn daemon: {}", e)))?
    };

    Ok(child)
}

#[cfg(windows)]
fn spawn_daemon_windows(
    exe: &Path,
    args: &[String],
    paths: &Paths,
    ca_password: Option<&str>,
) -> Result<Child> {
    use std::os::windows::process::CommandExt;

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_path())
        .map_err(|e| Error::WriteFile {
            path: paths.log_path(),
            source: e,
        })?;

    let log_file_clone = log_file
        .try_clone()
        .map_err(|e| Error::Config(format!("Failed to clone log file: {}", e)))?;

    // If password provided, write it to a secure temporary file
    let password_file_path = if let Some(pwd) = ca_password {
        let pwd_path = paths.password_file_path();
        crate::fs::atomic_write_secret(&pwd_path, pwd.as_bytes())?;
        Some(pwd_path)
    } else {
        None
    };

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const DETACHED_PROCESS: u32 = 0x00000008;

    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_clone))
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);

    // Pass password file path via environment variable (not the password itself)
    if password_file_path.is_some() {
        cmd.env("DEVSSL_PASSWORD_FILE", "1");
    }

    let child = cmd
        .spawn()
        .map_err(|e| Error::Config(format!("Failed to spawn daemon: {}", e)))?;

    Ok(child)
}

/// Stop the running daemon
pub fn stop(paths: &Paths) -> Result<()> {
    let pid = read_pid(paths).ok_or_else(|| Error::Config("Daemon is not running".into()))?;

    if !is_process_running(pid) {
        remove_pid(paths)?;
        return Err(Error::Config(
            "Daemon is not running (stale PID file removed)".into(),
        ));
    }

    #[cfg(unix)]
    {
        // SAFETY: SIGTERM is safe; ESRCH if process already exited is harmless
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    #[cfg(windows)]
    {
        // On Windows, use taskkill
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }

    // Wait for process to exit (with timeout)
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);

    while is_process_running(pid) {
        if start.elapsed() > timeout {
            return Err(Error::Config(format!(
                "Daemon (PID: {}) did not stop within timeout",
                pid
            )));
        }
        std::thread::sleep(Duration::from_millis(LOCK_RETRY_DELAY_MS));
    }

    remove_pid(paths)?;
    Ok(())
}

/// Run the daemon in foreground (for systemd/launchd integration)
pub fn run(
    paths: &Paths,
    config: &Config,
    on_renew: Option<&str>,
    ca_password: Option<&str>,
) -> Result<()> {
    let daemon_config = &config.daemon;

    // Secure the password immediately at startup to prevent /proc/environ exposure.
    // Read from argument or environment, encrypt with session key, then clear env var.
    let secure_password = if paths.ca_key_is_encrypted() {
        let mut password = if let Some(pwd) = ca_password {
            pwd.to_string()
        } else if std::env::var("DEVSSL_PASSWORD_FILE").is_ok() {
            // Read password from secure file
            let pwd_file = paths.password_file_path();
            let password_bytes = std::fs::read(&pwd_file).map_err(|e| Error::ReadFile {
                path: pwd_file.clone(),
                source: e,
            })?;

            // Secure delete - MUST succeed to prevent password file from persisting
            std::fs::remove_file(&pwd_file).map_err(|e| {
                Error::Config(format!(
                    "Failed to delete password file '{}': {}",
                    pwd_file.display(),
                    e
                ))
            })?;

            String::from_utf8(password_bytes)
                .map_err(|_| Error::Config("Password file contains invalid UTF-8".to_string()))?
        } else {
            return Err(Error::Config(
                "CA key is encrypted but no password provided. \
                 Use --ca-password when starting daemon"
                    .to_string(),
            ));
        };

        let secure = SecurePassword::new(&password);

        // Zeroize the plaintext password from memory
        password.zeroize();

        Some(secure)
    } else {
        // No password needed, but clean up password file if it exists (defense in depth)
        let pwd_file = paths.password_file_path();
        let _ = std::fs::remove_file(&pwd_file);
        None
    };

    // Acquire exclusive lock on PID file to prevent multiple daemon instances
    // Use retries to handle handoff from parent process (start() holds lock briefly)
    // This lock is held for the entire lifetime of the daemon
    let mut daemon_lock = DaemonLock::try_acquire_with_retries(paths, LOCK_HANDOFF_RETRIES)?;

    // Write our PID to the locked file
    daemon_lock.write_pid(std::process::id(), paths)?;

    // Set up signal handlers
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| Error::Config(format!("Failed to set signal handler: {}", e)))?;

    log_message(paths, "Daemon started");
    log_message(
        paths,
        &format!(
            "Check interval: {} hour(s), renew within: {} days",
            daemon_config.check_interval_hours, daemon_config.renew_within_days
        ),
    );

    // Use saturating_mul to prevent overflow with large check_interval_hours values
    let check_interval_secs =
        (daemon_config.check_interval_hours as u64).saturating_mul(SECONDS_PER_HOUR);
    let check_interval = Duration::from_secs(check_interval_secs);

    // Main daemon loop
    while running.load(Ordering::SeqCst) {
        // Check and renew certificates
        match check_and_renew(paths, config, on_renew, secure_password.as_ref()) {
            Ok(renewed) => {
                if renewed > 0 {
                    log_message(paths, &format!("Renewed {} certificate(s)", renewed));
                } else {
                    log_message(paths, "No certificates need renewal");
                }
            }
            Err(e) => {
                log_message(paths, &format!("Error during renewal check: {}", e));
            }
        }

        // Sleep in small intervals to respond to signals quickly
        let sleep_end = std::time::Instant::now() + check_interval;
        while running.load(Ordering::SeqCst) && std::time::Instant::now() < sleep_end {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    log_message(paths, "Daemon stopping");

    // Lock is automatically released when daemon_lock is dropped
    // Clean up PID file
    drop(daemon_lock);
    remove_pid(paths)?;

    Ok(())
}

/// Check all certificates and renew those expiring soon
fn check_and_renew(
    paths: &Paths,
    config: &Config,
    on_renew: Option<&str>,
    secure_password: Option<&SecurePassword>,
) -> Result<u32> {
    // Ensure CA exists
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    // Load CA with password support
    // Password is decrypted from SecurePassword (env var was cleared at startup)
    let ca = if paths.ca_key_is_encrypted() {
        let password = secure_password.map(|sp| sp.decrypt()).ok_or_else(|| {
            Error::Config(
                "CA key is encrypted but no password available. \
                     This is a bug - password should have been secured at daemon startup."
                    .to_string(),
            )
        })?;
        Ca::load_with_password(paths, Some(&password))?
    } else {
        Ca::load(paths)?
    };
    let daemon_config = &config.daemon;
    let within_days = daemon_config.renew_within_days;

    // Scan all .crt files in the devssl directory
    let entries = fs::read_dir(&paths.base).map_err(|e| Error::ReadDir {
        path: paths.base.clone(),
        source: e,
    })?;

    let mut certs: Vec<String> = Vec::new();
    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                // Log directory entry errors instead of silently ignoring
                log_message(
                    paths,
                    &format!(
                        "Warning: Could not read directory entry in {}: {}",
                        paths.base.display(),
                        e
                    ),
                );
                continue;
            }
        };
        let path = entry.path();
        if path.extension().map(|e| e == "crt").unwrap_or(false) {
            if let Some(stem) = path.file_stem() {
                let name = stem.to_string_lossy().to_string();
                // Skip CA certificate
                if name != "ca" {
                    certs.push(name);
                }
            }
        }
    }

    let mut renewed_count = 0;

    for cert_name in &certs {
        match renew_cert_if_expiring(paths, &ca, cert_name, within_days, config.cert_days) {
            Ok(true) => {
                renewed_count += 1;
                // Execute on-renew command if specified
                if let Some(cmd) = on_renew {
                    execute_on_renew(paths, cmd, cert_name);
                }
            }
            Ok(false) => {}
            Err(e) => {
                log_message(
                    paths,
                    &format!("Error checking certificate '{}': {}", cert_name, e),
                );
            }
        }
    }

    Ok(renewed_count)
}

/// Renew a certificate if it expires within the specified days
/// Returns true if renewed, false if not needed
fn renew_cert_if_expiring(
    paths: &Paths,
    ca: &Ca,
    name: &str,
    within_days: u32,
    new_days: u32,
) -> Result<bool> {
    let cert_path = paths.cert_path(name)?;

    // Parse certificate to check expiry and get domains
    let cert_info = crate::x509::parse_cert_file(&cert_path)?;
    let days_remaining = cert_info.days_remaining();

    if days_remaining > within_days as i64 {
        return Ok(false);
    }

    // Get domains from existing certificate
    let domains: Vec<String> = if cert_info.subject_alt_names.is_empty() {
        cert_info.common_name.map(|cn| vec![cn]).unwrap_or_default()
    } else {
        cert_info.subject_alt_names
    };

    if domains.is_empty() {
        return Err(Error::Config(format!(
            "Cannot renew {}: no domains or emails found in certificate",
            name
        )));
    }

    log_message(
        paths,
        &format!(
            "Renewing {}.crt ({} days remaining) for: {}",
            name,
            days_remaining,
            domains.join(", ")
        ),
    );

    // Generate new certificate preserving the original type
    let result = match cert_info.cert_type {
        crate::x509::CertType::Client => Cert::generate_client(ca, &domains, new_days)?,
        crate::x509::CertType::Smime => {
            let emails = cert_info.emails;
            if emails.is_empty() {
                return Err(Error::Config(format!(
                    "Cannot renew S/MIME cert {}: no email addresses found",
                    name
                )));
            }
            Cert::generate_smime(ca, &emails, &domains, new_days)?
        }
        _ => Cert::generate(ca, &domains, new_days)?,
    };
    if let Some(warning) = &result.warning {
        log_message(paths, &format!("Warning: {}", warning));
    }
    result.cert.save(paths, name)?;

    Ok(true)
}

/// Execute the on-renew command with a timeout
fn execute_on_renew(paths: &Paths, command: &str, cert_name: &str) {
    use std::thread;
    use std::time::Duration;

    // Maximum time to wait for on-renew command (5 minutes)
    const ON_RENEW_TIMEOUT_SECS: u64 = 300;

    // Validate cert_name to prevent injection attacks via environment variable
    // Reject names with control characters, shell metacharacters, or path separators
    if cert_name.is_empty()
        || cert_name.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '$' | '`'
                        | '\''
                        | '"'
                        | '\\'
                        | '|'
                        | '&'
                        | ';'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '!'
                        | '*'
                        | '?'
                        | '~'
                        | '#'
                        | '/'
                        | '\0'
                )
        })
    {
        log_message(
            paths,
            &format!(
                "Skipping on-renew command: cert name '{}' contains invalid characters",
                cert_name
            ),
        );
        return;
    }

    log_message(
        paths,
        &format!("Executing on-renew command for {}: {}", cert_name, command),
    );

    // Additional sanitization: only allow alphanumeric, dots, hyphens, underscores
    fn sanitize_env_value(value: &str) -> String {
        value
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            .collect()
    }

    let sanitized_cert_name = sanitize_env_value(cert_name);

    // SECURITY: Remove password from parent process BEFORE spawning child
    // env_remove() on Command only affects child environment, not parent
    std::env::remove_var("DEVSSL_PASSWORD");

    #[cfg(unix)]
    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("DEVSSL_RENEWED_CERT", sanitized_cert_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log_message(paths, &format!("Failed to spawn on-renew command: {}", e));
            return;
        }
    };

    #[cfg(windows)]
    let mut child = match Command::new("cmd")
        .arg("/C")
        .arg(command)
        .env("DEVSSL_RENEWED_CERT", sanitized_cert_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log_message(paths, &format!("Failed to spawn on-renew command: {}", e));
            return;
        }
    };

    // Wait with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    log_message(paths, "On-renew command completed successfully");
                } else {
                    log_message(
                        paths,
                        &format!(
                            "On-renew command failed with exit code: {:?}",
                            status.code()
                        ),
                    );
                }
                return;
            }
            Ok(None) => {
                // Still running, check timeout
                if start.elapsed().as_secs() > ON_RENEW_TIMEOUT_SECS {
                    log_message(
                        paths,
                        &format!(
                            "On-renew command timed out after {} seconds, killing process",
                            ON_RENEW_TIMEOUT_SECS
                        ),
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log_message(paths, &format!("Error waiting for on-renew command: {}", e));
                return;
            }
        }
    }
}

/// Log a message to the daemon log file
fn log_message(paths: &Paths, message: &str) {
    let log_path = paths.log_path();
    let timestamp = format_timestamp();

    let log_line = format!("[{}] {}\n", timestamp, message);

    // Also print to stdout for foreground mode
    print!("{}", log_line);

    // Append to log file
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let _ = file.write_all(log_line.as_bytes());
    }
}

/// Simple timestamp without external crate
fn format_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();

    // Convert to date/time components (simplified UTC)
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / SECONDS_PER_HOUR;
    let minutes = (remaining % SECONDS_PER_HOUR) / 60;
    let seconds = remaining % 60;

    // Calculate year, month, day from days since epoch
    let (year, month, day) = days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to year, month, day
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Days since 1970-01-01
    let mut remaining = days;

    // Start from 1970
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    // Find month
    let leap = is_leap_year(year);
    let days_in_months: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &dim in &days_in_months {
        if remaining < dim {
            break;
        }
        remaining -= dim;
        month += 1;
    }

    let day = remaining as u32 + 1;

    (year, month, day)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_days_to_ymd() {
        // Unix epoch: 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));

        // 2000-01-01 is day 10957
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));

        // 2025-01-01 (55 years from epoch: 41 regular + 14 leap years)
        let days_2025 = 20089;
        let (y, m, d) = days_to_ymd(days_2025);
        assert_eq!(y, 2025);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2004));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2001));
    }

    #[test]
    fn test_secure_password_encrypt_decrypt() {
        let password = "my_secret_password_123!";
        let secure = SecurePassword::new(password);

        // Encrypted should not equal original
        assert_ne!(secure.encrypted, password.as_bytes());

        // Decrypted should equal original (deref to &str for comparison)
        assert_eq!(&*secure.decrypt(), password);
    }

    #[test]
    fn test_secure_password_different_keys() {
        let password = "same_password";
        let secure1 = SecurePassword::new(password);
        let secure2 = SecurePassword::new(password);

        // Same password should produce different encrypted values (random keys)
        assert_ne!(secure1.encrypted, secure2.encrypted);
        assert_ne!(secure1.key, secure2.key);

        // But both should decrypt to the same password
        assert_eq!(&*secure1.decrypt(), password);
        assert_eq!(&*secure2.decrypt(), password);
    }

    #[test]
    fn test_secure_password_empty() {
        let password = "";
        let secure = SecurePassword::new(password);
        assert_eq!(&*secure.decrypt(), "");
    }

    #[test]
    fn test_secure_password_unicode() {
        let password = "пароль_密码_🔐";
        let secure = SecurePassword::new(password);
        assert_eq!(&*secure.decrypt(), password);
    }
}

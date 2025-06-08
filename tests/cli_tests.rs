//! Integration tests for the devssl CLI
//!
//! These tests run the actual devssl binary and verify its behavior.
//! Each test uses isolated temp directories via XDG_DATA_HOME.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Get the path to the devssl binary
fn devssl_bin() -> PathBuf {
    // Use the debug binary built by cargo
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("devssl")
}

/// Create a test environment with isolated directories
struct TestEnv {
    /// Temporary directory that will be cleaned up on drop
    _temp_dir: TempDir,
    /// The data directory where devssl stores its files
    data_dir: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        // Use DEVSSL_ROOT for cross-platform compatibility
        // (XDG_DATA_HOME is ignored on macOS by the directories crate)
        let data_dir = temp_dir.path().join("devssl");

        TestEnv {
            _temp_dir: temp_dir,
            data_dir,
        }
    }

    /// Run devssl command with isolated environment
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(devssl_bin())
            .args(args)
            // Use DEVSSL_ROOT instead of XDG_DATA_HOME for cross-platform compatibility
            .env("DEVSSL_ROOT", &self.data_dir)
            .env("HOME", self._temp_dir.path())
            .output()
            .expect("Failed to execute devssl")
    }

    /// Check if CA certificate exists
    fn ca_cert_exists(&self) -> bool {
        self.data_dir.join("ca.crt").exists()
    }

    /// Check if CA key exists
    fn ca_key_exists(&self) -> bool {
        self.data_dir.join("ca.key").exists()
    }

    /// Check if localhost certificate exists
    fn localhost_cert_exists(&self) -> bool {
        self.data_dir.join("localhost.crt").exists()
    }

    /// Check if localhost key exists
    fn localhost_key_exists(&self) -> bool {
        self.data_dir.join("localhost.key").exists()
    }

    /// Check if a domain certificate exists
    fn domain_cert_exists(&self, domain: &str) -> bool {
        self.data_dir.join(format!("{}.crt", domain)).exists()
    }

    /// Check if a domain key exists
    fn domain_key_exists(&self, domain: &str) -> bool {
        self.data_dir.join(format!("{}.key", domain)).exists()
    }

    /// Check if config file exists
    fn config_exists(&self) -> bool {
        self.data_dir.join("config.toml").exists()
    }

    /// Check if the data directory exists
    fn data_dir_exists(&self) -> bool {
        self.data_dir.exists()
    }
}

// ============================================================================
// Test: devssl init --skip-trust-store
// ============================================================================

#[test]
fn test_init_creates_ca_and_localhost_cert() {
    let env = TestEnv::new();

    // Run init with --skip-trust-store to avoid modifying system trust store
    let output = env.run(&["init", "--skip-trust-store"]);

    // Should succeed
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should create CA files
    assert!(env.ca_cert_exists(), "CA certificate was not created");
    assert!(env.ca_key_exists(), "CA key was not created");

    // Should create localhost certificate
    assert!(
        env.localhost_cert_exists(),
        "Localhost certificate was not created"
    );
    assert!(env.localhost_key_exists(), "Localhost key was not created");

    // Should create config
    assert!(env.config_exists(), "Config file was not created");

    // Verify output mentions skipping trust store
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Skipping trust store"),
        "Output should mention skipping trust store"
    );

    // Verify output mentions completion
    assert!(
        stdout.contains("Done!") || stdout.contains("ready to use"),
        "Output should indicate completion"
    );
}

#[test]
fn test_init_refuses_to_overwrite_without_force() {
    let env = TestEnv::new();

    // First init
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "First init should succeed");

    // Second init should fail
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(
        !output.status.success(),
        "Second init without --force should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("Error"),
        "Should report CA already exists"
    );
}

#[test]
fn test_init_with_force_regenerates_ca() {
    let env = TestEnv::new();

    // First init
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "First init should succeed");

    // Get modification time of CA cert
    let ca_cert_path = env.data_dir.join("ca.crt");
    let original_content = std::fs::read(&ca_cert_path).expect("Failed to read CA cert");

    // Small delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Second init with --force should succeed
    let output = env.run(&["init", "--skip-trust-store", "--force"]);
    assert!(
        output.status.success(),
        "Init with --force should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // CA cert should be regenerated (different content due to new key)
    let new_content = std::fs::read(&ca_cert_path).expect("Failed to read new CA cert");
    assert_ne!(
        original_content, new_content,
        "CA certificate should be regenerated with --force"
    );
}

// ============================================================================
// Test: devssl generate <domain> --skip-trust-store
// ============================================================================

#[test]
fn test_generate_creates_cert_for_domain() {
    let env = TestEnv::new();

    // First initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate certificate for test.local
    let output = env.run(&["generate", "test.local"]);

    assert!(
        output.status.success(),
        "Generate should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should create certificate files for the domain
    assert!(
        env.domain_cert_exists("test.local"),
        "Domain certificate was not created"
    );
    assert!(
        env.domain_key_exists("test.local"),
        "Domain key was not created"
    );

    // Verify output mentions the domain
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test.local"),
        "Output should mention the domain"
    );
}

#[test]
fn test_generate_fails_without_init() {
    let env = TestEnv::new();

    // Try to generate without init
    let output = env.run(&["generate", "test.local"]);

    assert!(
        !output.status.success(),
        "Generate without init should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error") || stderr.contains("not found") || stderr.contains("No such file"),
        "Should report CA not found"
    );
}

#[test]
fn test_generate_multiple_domains() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate certificate for multiple domains
    let output = env.run(&["generate", "app.local", "api.local", "admin.local"]);

    assert!(
        output.status.success(),
        "Generate should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should create certificate files (named after first domain)
    assert!(
        env.domain_cert_exists("app.local"),
        "Domain certificate was not created"
    );
    assert!(
        env.domain_key_exists("app.local"),
        "Domain key was not created"
    );

    // Verify output mentions all domains
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("app.local"),
        "Output should mention app.local"
    );
    assert!(
        stdout.contains("api.local"),
        "Output should mention api.local"
    );
    assert!(
        stdout.contains("admin.local"),
        "Output should mention admin.local"
    );
}

#[test]
fn test_generate_with_output_directory() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Create a custom output directory
    let output_dir = env._temp_dir.path().join("custom_certs");
    std::fs::create_dir_all(&output_dir).expect("Failed to create output dir");

    // Generate certificate with custom output
    let output = env.run(&[
        "generate",
        "custom.local",
        "--output",
        output_dir.to_str().unwrap(),
    ]);

    assert!(
        output.status.success(),
        "Generate with --output should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Certificate should be in custom directory
    assert!(
        output_dir.join("custom.local.crt").exists(),
        "Certificate should be in custom output directory"
    );
    assert!(
        output_dir.join("custom.local.key").exists(),
        "Key should be in custom output directory"
    );

    // Should NOT be in the default data directory
    assert!(
        !env.domain_cert_exists("custom.local"),
        "Certificate should NOT be in default directory"
    );
}

#[test]
fn test_generate_reserved_name_fails() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Try to generate certificate with reserved name "ca"
    let output = env.run(&["generate", "ca"]);

    assert!(
        !output.status.success(),
        "Generate with reserved name should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reserved") || stderr.contains("Error"),
        "Should report reserved name error"
    );
}

// ============================================================================
// Test: devssl status
// ============================================================================

#[test]
fn test_status_shows_not_initialized() {
    let env = TestEnv::new();

    let output = env.run(&["status"]);

    // Status should succeed even when not initialized
    assert!(
        output.status.success(),
        "Status should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not initialized") || stdout.contains("Run 'devssl init'"),
        "Output should indicate not initialized"
    );
}

#[test]
fn test_status_shows_ca_info() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Check status
    let output = env.run(&["status"]);

    assert!(
        output.status.success(),
        "Status should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show CA is initialized
    assert!(
        stdout.contains("CA:") && stdout.contains("initialized"),
        "Output should show CA is initialized"
    );

    // Should show CA path
    assert!(stdout.contains("Path:"), "Output should show CA path");

    // Should show CA expiry
    assert!(
        stdout.contains("Expires:"),
        "Output should show CA expiry date"
    );
}

#[test]
fn test_status_lists_certificates() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate additional certificate
    let output = env.run(&["generate", "myapp.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // Check status
    let output = env.run(&["status"]);

    assert!(
        output.status.success(),
        "Status should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should list certificates section
    assert!(
        stdout.contains("Certificates:"),
        "Output should have Certificates section"
    );

    // Should list localhost certificate
    assert!(
        stdout.contains("localhost"),
        "Output should list localhost certificate"
    );

    // Should list the generated certificate
    assert!(
        stdout.contains("myapp.local"),
        "Output should list myapp.local certificate"
    );
}

// ============================================================================
// Test: devssl uninstall --yes --keep-certs
// ============================================================================

#[test]
fn test_uninstall_with_keep_certs_preserves_files() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate additional certificate
    let output = env.run(&["generate", "myapp.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // Verify files exist before uninstall
    assert!(
        env.ca_cert_exists(),
        "CA cert should exist before uninstall"
    );
    assert!(
        env.localhost_cert_exists(),
        "Localhost cert should exist before uninstall"
    );
    assert!(
        env.domain_cert_exists("myapp.local"),
        "Domain cert should exist before uninstall"
    );

    // Uninstall with --keep-certs and --yes
    let output = env.run(&["uninstall", "--yes", "--keep-certs"]);

    assert!(
        output.status.success(),
        "Uninstall should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify output indicates uninstall
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Uninstalling") || stdout.contains("Done"),
        "Output should indicate uninstall"
    );

    // All certificate files should still exist
    assert!(
        env.ca_cert_exists(),
        "CA cert should exist after uninstall with --keep-certs"
    );
    assert!(
        env.ca_key_exists(),
        "CA key should exist after uninstall with --keep-certs"
    );
    assert!(
        env.localhost_cert_exists(),
        "Localhost cert should exist after uninstall with --keep-certs"
    );
    assert!(
        env.localhost_key_exists(),
        "Localhost key should exist after uninstall with --keep-certs"
    );
    assert!(
        env.domain_cert_exists("myapp.local"),
        "Domain cert should exist after uninstall with --keep-certs"
    );
    assert!(
        env.domain_key_exists("myapp.local"),
        "Domain key should exist after uninstall with --keep-certs"
    );
    assert!(
        env.config_exists(),
        "Config should exist after uninstall with --keep-certs"
    );
}

#[test]
fn test_uninstall_without_keep_certs_removes_files() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate additional certificate
    let output = env.run(&["generate", "myapp.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // Verify files exist before uninstall
    assert!(
        env.data_dir_exists(),
        "Data dir should exist before uninstall"
    );
    assert!(
        env.ca_cert_exists(),
        "CA cert should exist before uninstall"
    );

    // Uninstall without --keep-certs (with --yes to skip prompt)
    let output = env.run(&["uninstall", "--yes"]);

    assert!(
        output.status.success(),
        "Uninstall should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Data directory should be removed
    assert!(
        !env.data_dir_exists(),
        "Data directory should be removed after uninstall"
    );
}

#[test]
fn test_uninstall_without_yes_requires_confirmation() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Uninstall without --yes should prompt (and fail since no input is provided)
    let output = env.run(&["uninstall"]);

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should ask for confirmation
    assert!(
        stdout.contains("Continue?") || stdout.contains("[y/N]"),
        "Should prompt for confirmation"
    );

    // Files should still exist since we didn't confirm
    assert!(
        env.ca_cert_exists(),
        "CA cert should still exist after declined uninstall"
    );
}

// ============================================================================
// Additional edge case tests
// ============================================================================

#[test]
fn test_init_with_custom_days() {
    let env = TestEnv::new();

    // Run init with custom days
    let output = env.run(&["init", "--skip-trust-store", "--days", "7"]);

    assert!(
        output.status.success(),
        "init with --days should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify files were created
    assert!(env.ca_cert_exists(), "CA certificate was not created");
    assert!(
        env.localhost_cert_exists(),
        "Localhost certificate was not created"
    );
}

#[test]
fn test_generate_with_custom_days() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate certificate with custom days
    let output = env.run(&["generate", "test.local", "--days", "90"]);

    assert!(
        output.status.success(),
        "Generate with --days should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        env.domain_cert_exists("test.local"),
        "Domain certificate was not created"
    );
}

#[test]
fn test_wildcard_domain() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate wildcard certificate
    let output = env.run(&["generate", "*.local"]);

    assert!(
        output.status.success(),
        "Generate wildcard should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Wildcard * is replaced with _wildcard_ in filename
    assert!(
        env.domain_cert_exists("_wildcard_.local"),
        "Wildcard certificate was not created"
    );
    assert!(
        env.domain_key_exists("_wildcard_.local"),
        "Wildcard key was not created"
    );
}

#[test]
fn test_help_command() {
    let env = TestEnv::new();

    let output = env.run(&["--help"]);

    assert!(output.status.success(), "Help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("devssl") && stdout.contains("HTTPS"),
        "Help should describe devssl"
    );
    assert!(stdout.contains("init"), "Help should list init command");
    assert!(
        stdout.contains("generate"),
        "Help should list generate command"
    );
    assert!(stdout.contains("status"), "Help should list status command");
    assert!(
        stdout.contains("uninstall"),
        "Help should list uninstall command"
    );
}

#[test]
fn test_version_command() {
    let env = TestEnv::new();

    let output = env.run(&["--version"]);

    assert!(output.status.success(), "Version should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("devssl"),
        "Version output should contain devssl"
    );
}

// ============================================================================
// Test: devssl renew
// ============================================================================

#[test]
fn test_renew_specific_cert() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate a certificate with short validity (1 day)
    let output = env.run(&["generate", "expiring.local", "--days", "1"]);
    assert!(output.status.success(), "Generate should succeed");

    // Renew the specific certificate
    let output = env.run(&[
        "renew",
        "expiring.local",
        "--within-days",
        "7",
        "--days",
        "30",
    ]);
    assert!(
        output.status.success(),
        "Renew should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the certificate still exists
    assert!(
        env.domain_cert_exists("expiring.local"),
        "Certificate should exist after renewal"
    );
}

#[test]
fn test_renew_all_certs() {
    let env = TestEnv::new();

    // Initialize with short validity
    let output = env.run(&["init", "--skip-trust-store", "--days", "1"]);
    assert!(output.status.success(), "Init should succeed");

    // Renew all certificates
    let output = env.run(&["renew", "--within-days", "7"]);
    assert!(
        output.status.success(),
        "Renew should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should mention checking certificates
    assert!(
        stdout.contains("Checking") || stdout.contains("Renew") || stdout.contains("localhost"),
        "Output should show renew activity"
    );
}

#[test]
fn test_renew_nonexistent_cert() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Try to renew a non-existent certificate
    let output = env.run(&["renew", "nonexistent.local"]);
    assert!(
        !output.status.success(),
        "Renew of non-existent cert should fail"
    );
}

#[test]
fn test_generate_force_overwrites_existing() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate certificate for test.local
    let output = env.run(&["generate", "test.local"]);
    assert!(output.status.success(), "First generate should succeed");

    // Get original cert content
    let cert_path = env.data_dir.join("test.local.crt");
    let original_content = std::fs::read(&cert_path).expect("Failed to read cert");

    // Small delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Try to generate again without --force (should fail with error)
    let output = env.run(&["generate", "test.local"]);
    assert!(
        !output.status.success(),
        "Second generate should fail when cert exists"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "Should indicate cert exists"
    );

    // Content should be unchanged
    let unchanged_content = std::fs::read(&cert_path).expect("Failed to read cert");
    assert_eq!(
        original_content, unchanged_content,
        "Certificate should not be overwritten without --force"
    );

    // Generate with --force should overwrite
    let output = env.run(&["generate", "test.local", "--force"]);
    assert!(
        output.status.success(),
        "Generate with --force should succeed"
    );

    // Content should be different (new key)
    let new_content = std::fs::read(&cert_path).expect("Failed to read cert");
    assert_ne!(
        original_content, new_content,
        "Certificate should be overwritten with --force"
    );
}

#[test]
fn test_renew_no_certs_need_renewal() {
    let env = TestEnv::new();

    // Initialize with long validity (30 days default)
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Try to renew with short threshold (should find nothing to renew)
    let output = env.run(&["renew", "--within-days", "1"]);
    assert!(
        output.status.success(),
        "Renew should succeed even with nothing to renew"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No certificates needed renewal") || stdout.contains("Checking"),
        "Should indicate no renewals needed"
    );
}

// ============================================================================
// Test: devssl proxy
// ============================================================================

#[test]
fn test_proxy_fails_without_init() {
    let env = TestEnv::new();

    // Try to run proxy without init
    let output = env.run(&["proxy", "3000"]);

    assert!(!output.status.success(), "Proxy without init should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not initialized") || stderr.contains("Error"),
        "Should report CA not initialized"
    );
}

#[test]
fn test_proxy_help_shows_options() {
    let env = TestEnv::new();

    let output = env.run(&["proxy", "--help"]);

    assert!(output.status.success(), "Proxy help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("port"), "Help should mention port");
    assert!(stdout.contains("--host"), "Help should mention --host");
    assert!(
        stdout.contains("--https-port"),
        "Help should mention --https-port"
    );
}

// ============================================================================
// Test: devssl list
// ============================================================================

#[test]
fn test_list_fails_without_init() {
    let env = TestEnv::new();

    let output = env.run(&["list"]);

    // Should fail when not initialized
    assert!(!output.status.success(), "List without init should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not initialized") || stderr.contains("Error"),
        "Should indicate CA not initialized"
    );
}

#[test]
fn test_list_shows_certificates() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate additional certificate
    let output = env.run(&["generate", "myapp.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // List certificates
    let output = env.run(&["list"]);

    assert!(
        output.status.success(),
        "List should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should list localhost certificate
    assert!(
        stdout.contains("localhost"),
        "Output should list localhost certificate"
    );

    // Should list the generated certificate
    assert!(
        stdout.contains("myapp.local"),
        "Output should list myapp.local certificate"
    );
}

// ============================================================================
// Test: devssl inspect
// ============================================================================

#[test]
fn test_inspect_shows_certificate_details() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Inspect localhost certificate
    let output = env.run(&["inspect", "localhost"]);

    assert!(
        output.status.success(),
        "Inspect should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show certificate details
    assert!(
        stdout.contains("localhost"),
        "Output should show certificate name"
    );
    assert!(
        stdout.contains("Expires") || stdout.contains("Valid"),
        "Output should show validity information"
    );
}

#[test]
fn test_inspect_nonexistent_certificate() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Try to inspect non-existent certificate
    let output = env.run(&["inspect", "nonexistent.local"]);

    assert!(
        !output.status.success(),
        "Inspect of non-existent cert should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Error"),
        "Should report certificate not found"
    );
}

// ============================================================================
// Test: devssl chain
// ============================================================================

#[test]
fn test_chain_exports_certificate_chain() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Export chain for localhost
    let output = env.run(&["chain", "localhost"]);

    assert!(
        output.status.success(),
        "Chain should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain certificate markers (PEM format)
    assert!(
        stdout.contains("-----BEGIN CERTIFICATE-----"),
        "Output should contain certificate in PEM format"
    );

    // Should contain at least two certificates (cert + CA)
    let cert_count = stdout.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(
        cert_count >= 2,
        "Chain should contain at least 2 certificates, found {}",
        cert_count
    );
}

#[test]
fn test_chain_exports_to_file() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Create output file path
    let output_file = env._temp_dir.path().join("chain.pem");

    // Export chain to file
    let output = env.run(&[
        "chain",
        "localhost",
        "--output",
        output_file.to_str().unwrap(),
    ]);

    assert!(
        output.status.success(),
        "Chain with --output should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // File should exist and contain certificates
    assert!(output_file.exists(), "Chain file should be created");

    let contents = std::fs::read_to_string(&output_file).expect("Failed to read chain file");
    assert!(
        contents.contains("-----BEGIN CERTIFICATE-----"),
        "Chain file should contain certificates"
    );
}

#[test]
fn test_chain_nonexistent_certificate() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Try to export chain for non-existent certificate
    let output = env.run(&["chain", "nonexistent.local"]);

    assert!(
        !output.status.success(),
        "Chain of non-existent cert should fail"
    );
}

// ============================================================================
// Test: devssl backup and restore
// ============================================================================

#[test]
fn test_backup_creates_backup_directory() {
    let env = TestEnv::new();

    // Initialize
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Generate additional certificate
    let output = env.run(&["generate", "myapp.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // Create backup directory path
    let backup_dir = env._temp_dir.path().join("backup");

    // Create backup
    let output = env.run(&["backup", "--output", backup_dir.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "Backup should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Backup directory should exist
    assert!(backup_dir.exists(), "Backup directory should be created");

    // Should contain CA files
    assert!(
        backup_dir.join("ca.crt").exists(),
        "Backup should contain CA certificate"
    );
    assert!(
        backup_dir.join("ca.key").exists(),
        "Backup should contain CA key"
    );

    // Should contain localhost certificate
    assert!(
        backup_dir.join("localhost.crt").exists(),
        "Backup should contain localhost certificate"
    );

    // Should contain generated certificate
    assert!(
        backup_dir.join("myapp.local.crt").exists(),
        "Backup should contain myapp.local certificate"
    );
}

#[test]
fn test_restore_from_backup() {
    let env = TestEnv::new();

    // Initialize and generate certificate
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["generate", "restore-test.local"]);
    assert!(output.status.success(), "Generate should succeed");

    // Create backup
    let backup_dir = env._temp_dir.path().join("backup");
    let output = env.run(&["backup", "--output", backup_dir.to_str().unwrap()]);
    assert!(output.status.success(), "Backup should succeed");

    // Uninstall (removes all files)
    let output = env.run(&["uninstall", "--yes"]);
    assert!(output.status.success(), "Uninstall should succeed");

    // Verify files are gone
    assert!(!env.ca_cert_exists(), "CA cert should be removed");

    // Restore from backup
    let output = env.run(&["restore", backup_dir.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "Restore should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify files are restored
    assert!(env.ca_cert_exists(), "CA cert should be restored");
    assert!(env.ca_key_exists(), "CA key should be restored");
    assert!(
        env.localhost_cert_exists(),
        "Localhost cert should be restored"
    );
    assert!(
        env.domain_cert_exists("restore-test.local"),
        "Generated cert should be restored"
    );
}

#[test]
fn test_restore_nonexistent_backup() {
    let env = TestEnv::new();

    // Try to restore from non-existent directory
    let output = env.run(&["restore", "/nonexistent/backup/path"]);

    assert!(
        !output.status.success(),
        "Restore from non-existent path should fail"
    );
}

// ============================================================================
// Test: devssl trust
// ============================================================================

#[test]
fn test_trust_status_not_initialized() {
    let env = TestEnv::new();

    let output = env.run(&["trust", "status"]);

    // Should succeed or fail gracefully
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("not initialized")
            || combined.contains("not found")
            || combined.contains("Error"),
        "Should indicate CA not initialized"
    );
}

#[test]
fn test_trust_status_after_init() {
    let env = TestEnv::new();

    // Initialize (skipping trust store so it won't be installed)
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Check trust status
    let output = env.run(&["trust", "status"]);

    assert!(
        output.status.success(),
        "Trust status should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show some trust information (may not be trusted since we skipped)
    assert!(
        stdout.contains("Trust") || stdout.contains("CA") || stdout.contains("not trusted"),
        "Output should show trust status information"
    );
}

#[test]
fn test_trust_help() {
    let env = TestEnv::new();

    let output = env.run(&["trust", "--help"]);

    assert!(output.status.success(), "Trust help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("install"), "Help should mention install");
    assert!(stdout.contains("remove"), "Help should mention remove");
    assert!(stdout.contains("status"), "Help should mention status");
}

// ============================================================================
// Test: devssl init --ci
// ============================================================================

#[test]
fn test_init_ci_mode() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--ci"]);

    assert!(
        output.status.success(),
        "Init with --ci should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should create CA and localhost cert
    assert!(env.ca_cert_exists(), "CA cert should be created in CI mode");
    assert!(
        env.localhost_cert_exists(),
        "Localhost cert should be created in CI mode"
    );
}

#[test]
fn test_init_with_node_flag() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store", "--node"]);

    assert!(
        output.status.success(),
        "Init with --node should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NODE_EXTRA_CA_CERTS"),
        "Output should contain NODE_EXTRA_CA_CERTS export"
    );
}

#[test]
fn test_init_with_trust_stores() {
    let env = TestEnv::new();

    // This may or may not succeed depending on system, just verify flag is accepted
    let output = env.run(&["init", "--skip-trust-store", "--trust-stores", "system"]);

    assert!(
        output.status.success(),
        "Init with --trust-stores should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Test: devssl generate --pkcs12, --client, --email
// ============================================================================

#[test]
fn test_generate_with_pkcs12() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["generate", "pkcs12.local", "--pkcs12"]);

    assert!(
        output.status.success(),
        "Generate with --pkcs12 should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should create .p12 file
    assert!(
        env.data_dir.join("pkcs12.local.p12").exists(),
        "PKCS12 file should be created"
    );
}

#[test]
fn test_generate_client_cert() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["generate", "client.local", "--client"]);

    assert!(
        output.status.success(),
        "Generate with --client should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        env.domain_cert_exists("client.local"),
        "Client cert should be created"
    );
}

#[test]
fn test_generate_smime_email_cert() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["generate", "--email", "test@example.local"]);

    assert!(
        output.status.success(),
        "Generate with --email should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Email certs use underscores in filename (@ -> _at_)
    assert!(
        env.data_dir.join("test_at_example_local.crt").exists(),
        "S/MIME cert should be created"
    );
}

// ============================================================================
// Test: devssl path
// ============================================================================

#[test]
fn test_path_shows_certificate_paths() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["path", "localhost"]);

    assert!(
        output.status.success(),
        "Path should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(".crt"), "Output should show cert path");
    assert!(stdout.contains(".key"), "Output should show key path");
}

#[test]
fn test_path_without_args_shows_ca() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["path"]);

    assert!(
        output.status.success(),
        "Path without args should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ca"), "Output should show CA path");
}

// ============================================================================
// Test: devssl export-ca and import-ca
// ============================================================================

#[test]
fn test_export_ca_pem() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["export-ca"]);

    assert!(
        output.status.success(),
        "Export CA should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("-----BEGIN CERTIFICATE-----"),
        "Output should be PEM format"
    );
}

#[test]
fn test_export_ca_to_file() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let export_path = env._temp_dir.path().join("exported-ca.pem");
    let output = env.run(&["export-ca", "--output", export_path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "Export CA to file should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(export_path.exists(), "Export file should exist");
}

#[test]
fn test_export_ca_der_format() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let export_path = env._temp_dir.path().join("exported-ca.der");
    let output = env.run(&[
        "export-ca",
        "--output",
        export_path.to_str().unwrap(),
        "--format",
        "der",
    ]);

    assert!(
        output.status.success(),
        "Export CA in DER format should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(export_path.exists(), "DER export file should exist");
}

#[test]
fn test_import_ca() {
    use std::io::Write;
    use std::process::Stdio;

    let env = TestEnv::new();

    // First create a CA
    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Export it
    let export_path = env._temp_dir.path().join("ca-export.pem");
    let output = env.run(&["export-ca", "--output", export_path.to_str().unwrap()]);
    assert!(output.status.success(), "Export should succeed");

    // Create new env and import (need to provide "y" for confirmation prompt)
    let env2 = TestEnv::new();
    let mut child = Command::new(devssl_bin())
        .args(["import-ca", export_path.to_str().unwrap()])
        .env("DEVSSL_ROOT", &env2.data_dir)
        .env("HOME", env2._temp_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn import-ca");

    // Write "y" to confirm
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\n");
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait on import-ca");

    assert!(
        output.status.success(),
        "Import CA should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(env2.ca_cert_exists(), "CA cert should exist after import");
}

// ============================================================================
// Test: devssl completions
// ============================================================================

#[test]
fn test_completions_bash() {
    let env = TestEnv::new();

    let output = env.run(&["completions", "bash"]);

    assert!(
        output.status.success(),
        "Bash completions should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Completions should not be empty");
}

#[test]
fn test_completions_zsh() {
    let env = TestEnv::new();

    let output = env.run(&["completions", "zsh"]);

    assert!(
        output.status.success(),
        "Zsh completions should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_completions_fish() {
    let env = TestEnv::new();

    let output = env.run(&["completions", "fish"]);

    assert!(
        output.status.success(),
        "Fish completions should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Test: devssl nginx, traefik, docker-compose
// ============================================================================

#[test]
fn test_nginx_config() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["nginx", "localhost"]);

    assert!(
        output.status.success(),
        "Nginx config should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ssl_certificate"),
        "Should contain nginx SSL config"
    );
}

#[test]
fn test_traefik_config() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["traefik", "localhost"]);

    assert!(
        output.status.success(),
        "Traefik config should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("tls") || stdout.contains("certFile"),
        "Should contain Traefik TLS config"
    );
}

#[test]
fn test_docker_compose_config() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["docker-compose", "localhost"]);

    assert!(
        output.status.success(),
        "Docker compose config should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("volumes") || stdout.contains("environment"),
        "Should contain docker-compose config"
    );
}

// ============================================================================
// Test: devssl doctor
// ============================================================================

#[test]
fn test_doctor_not_initialized() {
    let env = TestEnv::new();

    let output = env.run(&["doctor"]);

    // Doctor should work even without init
    assert!(output.status.success(), "Doctor should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CA") || stdout.contains("certificate") || stdout.contains("Check"),
        "Doctor should report status"
    );
}

#[test]
fn test_doctor_after_init() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let output = env.run(&["doctor"]);

    assert!(
        output.status.success(),
        "Doctor should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Test: devssl qr
// ============================================================================

#[test]
fn test_qr_save_to_file() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    let qr_path = env._temp_dir.path().join("qr.png");
    let output = env.run(&["qr", "--save", qr_path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "QR save should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(qr_path.exists(), "QR file should be created");
}

// ============================================================================
// Test: devssl daemon
// ============================================================================

#[test]
fn test_daemon_help() {
    let env = TestEnv::new();

    let output = env.run(&["daemon", "--help"]);

    assert!(output.status.success(), "Daemon help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("start"), "Help should mention start");
    assert!(stdout.contains("stop"), "Help should mention stop");
    assert!(stdout.contains("status"), "Help should mention status");
}

#[test]
fn test_daemon_status_not_running() {
    let env = TestEnv::new();

    let output = env.run(&["daemon", "status"]);

    // Should succeed even when not running
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("not running") || combined.contains("Daemon"),
        "Should indicate daemon status"
    );
}

// ============================================================================
// Test: devssl encrypt-key, decrypt-key, change-password
// ============================================================================

#[test]
fn test_encrypt_decrypt_key() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Encrypt the key
    let output = env.run(&["encrypt-key", "--password", "testpass123"]);
    assert!(
        output.status.success(),
        "Encrypt key should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Decrypt the key
    let output = env.run(&["decrypt-key", "--password", "testpass123"]);
    assert!(
        output.status.success(),
        "Decrypt key should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_change_password() {
    let env = TestEnv::new();

    let output = env.run(&["init", "--skip-trust-store"]);
    assert!(output.status.success(), "Init should succeed");

    // Encrypt the key first
    let output = env.run(&["encrypt-key", "--password", "oldpass"]);
    assert!(output.status.success(), "Encrypt should succeed");

    // Change password
    let output = env.run(&[
        "change-password",
        "--old-password",
        "oldpass",
        "--new-password",
        "newpass",
    ]);
    assert!(
        output.status.success(),
        "Change password should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify new password works by decrypting
    let output = env.run(&["decrypt-key", "--password", "newpass"]);
    assert!(
        output.status.success(),
        "Decrypt with new password should succeed"
    );
}

// ============================================================================
// Test: Global flags
// ============================================================================

#[test]
fn test_quiet_flag() {
    let env = TestEnv::new();

    let output = env.run(&["-q", "init", "--skip-trust-store"]);

    assert!(
        output.status.success(),
        "Init with -q should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Quiet mode should produce minimal output
    let _stdout = String::from_utf8_lossy(&output.stdout);
    // Output should be less verbose (exact behavior depends on implementation)
    assert!(
        env.ca_cert_exists(),
        "CA should still be created in quiet mode"
    );
}

#[test]
fn test_verbose_flag() {
    let env = TestEnv::new();

    let output = env.run(&["-v", "init", "--skip-trust-store"]);

    assert!(
        output.status.success(),
        "Init with -v should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(env.ca_cert_exists(), "CA should be created in verbose mode");
}

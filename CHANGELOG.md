# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-01-02

### Security

- **Fixed panic risk in proxy error handlers** - Replaced `.unwrap()` calls with panic-free alternatives
  - Proxy now safely logs errors instead of crashing on malformed error responses
  - Ensures production code upholds "zero panic" guarantee

### Added

- **DEVSSL_ROOT validation** - Prevents accidental certificate writes to system directories
  - Hard fail when DEVSSL_ROOT points to `/etc`, `/usr`, `/bin`, `/var`, `/tmp`, etc.
  - Set `DEVSSL_ALLOW_SYSTEM_PATHS=1` to override for testing/CI environments
  - Prevents permission errors and security issues from misconfiguration

## [0.2.0] - 2026-01-02

### Added

- **`devssl delete` command** - Delete certificates with confirmation prompt
  - `--force` flag to skip confirmation
  - `--keep-key` flag to preserve private key while removing certificate
  - Automatically removes associated PKCS12 files
- **Firefox NSS and Java keystore support for macOS and Windows**
  - Automatically detects and installs CA in Firefox profiles
  - Supports Java cacerts keystore integration
- **Configurable proxy body size limit**
  - `--max-body-size` flag supports human-readable formats (10MB, 1G, etc.)
  - Prevents integer overflow with validation
  - Default remains 10MB for backward compatibility
- **Enhanced `devssl inspect` output**
  - Shows issued date with full timestamp
  - Displays SHA-256 fingerprint for verification
  - Includes key usage and extended key usage information
  - Better formatted validity status
- **Proxy auto-trust** - Automatically adds CA to trust store when generating certificates on-the-fly
- **API documentation** - Added comprehensive doc comments to public APIs in `ca.rs`, `cert.rs`, and `proxy.rs`

### Changed

- **BREAKING**: Renamed `--host` flag to `--cert` in proxy command for clarity
  - The flag now clearly indicates it selects which certificate to use, not the bind address
  - Migration: Replace `--host myapp.local` with `--cert myapp.local`
- **`devssl list` now shows domains column**
  - Displays abbreviated domain list by default (e.g., "localhost +2")
  - Use `--verbose` flag to show all domains
- **Test improvements** - Replaced `.unwrap()` with `.expect()` for better error messages

### Fixed

- **Proxy graceful shutdown** - Properly drains in-flight connections on Ctrl+C
  - 5-second timeout for active connections before forced termination
  - Coordinated shutdown between HTTPS proxy and HTTP redirect server
  - Prevents abrupt connection termination for persistent HTTP/1.1 connections
- **QR server clock skew** - Switched from `SystemTime` to `Instant` for monotonic timeout handling
- **Integer overflow in size parsing** - Added validation to prevent overflow when parsing `--max-body-size`
- **Export-ca with encrypted keys** - `--ca-password` flag now properly supports encrypted CA keys

### Improved

- **Configuration generator documentation** - Added comments noting outputs are minimal examples for development
- **IP address documentation** - Clarified in help text and README that IP addresses are supported alongside domains
- **README proxy section** - Added usage examples for large uploads, mobile testing, and HTTP redirects
- **Proxy notes** - Documented auto-generation behavior, required headers, and body size limits

## [0.1.2] - 2026-01-01

### Fixed

- Proxy now sends proper forwarding headers (`X-Forwarded-Proto`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`) for correct HTTPS detection by backend apps
- Proxy uses original `Host` header instead of backend address for proper app routing

## [0.1.1] - 2026-06-08

### Fixed

- Cross-platform test compatibility for macOS and Windows CI

## [0.1.0] - 2025-06-08

### Added

#### Core Features

- Zero-config local HTTPS certificate generation
- Automatic CA certificate management
- Multi-domain and wildcard certificate support
- Client certificates for mTLS
- S/MIME certificates for email encryption
- Certificate Signing Request (CSR) support
- PKCS#12 (.p12) export
- Configuration file support (`config.toml`)

#### Trust Store Integration

- Linux (Debian/Ubuntu, Fedora/RHEL, Arch)
- macOS Keychain
- Windows Certificate Store
- Firefox NSS database
- Java keystore (cacerts)

#### Tools & Commands

- HTTPS reverse proxy with WebSocket support
- Background auto-renewal daemon
- QR code generation for mobile setup
- Certificate backup and restore
- CA key encryption with password protection
- Configuration generators (nginx, traefik, docker-compose)
- Framework detection (20+ frameworks)
- Shell completions (bash, zsh, fish, powershell, elvish)
- Doctor command for diagnostics

#### Distribution

- Pre-built binaries: Linux (x64/ARM64, glibc/musl), macOS (Intel/Apple Silicon), Windows (x64)
- Homebrew: `brew install jayashankarvr/tap/devssl`
- AUR: `yay -S devssl`
- Debian/Ubuntu: .deb packages
- Fedora/RHEL: .rpm packages
- Cargo: `cargo install devssl`

#### Security & Quality

- Secure password handling with zeroization
- PKCS#8 AES-256-CBC key encryption
- Input validation (path traversal, injection prevention)
- No panic!() in production code
- 143 automated tests with CI/CD
- Framework integration examples
- Comprehensive documentation (README, CONTRIBUTING, SECURITY)

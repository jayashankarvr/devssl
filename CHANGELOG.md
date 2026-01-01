# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

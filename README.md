# devssl

[![CI](https://github.com/jayashankarvr/devssl/actions/workflows/ci.yml/badge.svg)](https://github.com/jayashankarvr/devssl/actions/workflows/ci.yml)
[![Release](https://github.com/jayashankarvr/devssl/actions/workflows/release.yml/badge.svg)](https://github.com/jayashankarvr/devssl/actions/workflows/release.yml)
[![Crates.io](https://img.shields.io/crates/v/devssl.svg)](https://crates.io/crates/devssl)
[![MSRV](https://img.shields.io/badge/MSRV-1.70-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Trusted HTTPS certificates for localhost. No browser warnings.

## Features

- Zero-config HTTPS for local development
- Automatic trust store installation (macOS Keychain, Linux system store, Windows certutil)
- HTTPS reverse proxy with WebSocket support
- Auto-renewal daemon
- Backup and restore certificates
- Team CA sharing
- S/MIME email certificates
- Client authentication certificates

## Installation

### Homebrew (macOS)

```bash
brew tap jayashankarvr/devssl
brew install devssl
```

### Cargo

```bash
cargo install devssl
```

### From Source

```bash
git clone https://github.com/jayashankarvr/devssl.git
cd devssl
cargo install --path .
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/jayashankarvr/devssl/releases).

## Quick Start

```bash
devssl init
```

## Usage

```bash
# Initial setup (creates CA, adds to trust store, generates localhost cert)
devssl init

# Generate cert for custom domains
devssl generate myapp.local api.myapp.local

# HTTPS proxy (terminates TLS, forwards to HTTP backend)
devssl proxy 3000            # Forward to localhost:3000
devssl proxy 192.168.1.5:8080  # Forward to specific host:port

# Check status
devssl status

# List all certificates
devssl list

# Renew expiring certs
devssl renew
devssl renew --force         # Force renewal even if not expiring
devssl renew --dry-run       # Show what would be renewed

# Backup and restore
devssl backup                # Backup CA and all certs
devssl restore ./devssl-backup  # Restore from backup

# Manage trust store
devssl trust status          # Check if CA is trusted
devssl trust install         # Add CA to trust store
devssl trust remove          # Remove CA from trust store
```

### Global Flags

All commands support these flags:

| Flag            | Description                   |
|-----------------|-------------------------------|
| `-q, --quiet`   | Suppress non-essential output |
| `-v, --verbose` | Show detailed operation logs  |

Certificate files are stored in:

- Linux: `~/.local/share/devssl/`
- macOS: `~/Library/Application Support/devssl/`
- Windows: `%LOCALAPPDATA%\devssl\`

## Commands

### init

```bash
devssl init [--force] [--skip-trust-store] [--ci] [--days N] [--node] [--detect] [--encrypt] [--ca-password PWD]
```

Creates CA, adds to system trust store, generates localhost certificate.

| Flag            | Description                                                           |
|-----------------|-----------------------------------------------------------------------|
| `--days N`      | Days until localhost certificate expires (default: config value, 365) |
| `--ci`          | Skip trust store installation (for CI/Docker)                         |
| `--node`        | Print `NODE_EXTRA_CA_CERTS` export command                            |
| `--detect`      | Auto-detect framework and show configuration hints                    |
| `--encrypt`     | Encrypt CA private key with a password                                |
| `--ca-password` | Password for CA key encryption (requires `--encrypt`)                 |

### generate

```bash
devssl generate <domains...> [--days N] [--output DIR] [--force] [--ca-password PWD] [OPTIONS]
```

Creates certificate for specified domain names or IP addresses. Supports `.local`, `.test`, `.internal`, and other private TLDs, as well as private IP addresses (e.g., `192.168.1.100`, `10.0.0.5`).

| Flag               | Description                                                                            |
|--------------------|----------------------------------------------------------------------------------------|
| `--days N`         | Days until certificate expires (default: 30)                                           |
| `--ca-password`    | Password for encrypted CA key                                                          |
| `--csr <FILE>`     | Sign a Certificate Signing Request instead of generating new key                       |
| `--pkcs12`         | Export as PKCS12 (.p12) file alongside .crt/.key                                       |
| `--password <PWD>` | Password for PKCS12 file (default: empty)                                              |
| `--client`         | Generate client authentication certificate                                             |
| `--email <ADDR>`   | Generate S/MIME certificate for email signing (can be repeated for multiple addresses) |

### proxy

```bash
devssl proxy <backend> [--cert NAME] [--https-port PORT] [--redirect] [--http-port PORT] [--bind ADDR] [--max-body-size SIZE] [--ca-password PWD]
```

Runs HTTPS reverse proxy. Forwards to HTTP backend. The `<backend>` parameter accepts either a port number (e.g., `3000`) or a host:port address (e.g., `192.168.1.5:8080`).

| Flag                    | Description                                                                          |
|-------------------------|--------------------------------------------------------------------------------------|
| `--cert NAME`           | Certificate name to use (default: localhost)                                         |
| `--https-port PORT`     | HTTPS port to listen on (default: same as backend port)                              |
| `--redirect`            | Also listen on HTTP and redirect to HTTPS                                            |
| `--http-port PORT`      | HTTP port for redirects (default: 8080)                                              |
| `--bind ADDR`           | Address to bind the proxy to (default: 127.0.0.1). Use 0.0.0.0 for mobile/VM testing |
| `--max-body-size SIZE`  | Maximum request/response body size (default: 10MB). Supports K/KB, M/MB, G/GB        |
| `--ca-password`         | Password for encrypted CA key                                                        |

**Examples:**

```bash
# Large file uploads
devssl proxy 3000 --max-body-size 100MB

# Mobile testing with specific cert
devssl proxy 3000 --bind 0.0.0.0 --cert myapp.local

# Redirect HTTP to HTTPS
devssl proxy 3000 --redirect --http-port 80
```

**Notes:**

- The proxy automatically generates certificates if they don't exist
- Backend must accept proxied headers (`X-Forwarded-Proto`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`)
- Default body size limit is 10MB (configurable with `--max-body-size`)

### renew

```bash
devssl renew [NAME] [--within-days N] [--days N] [--force] [--dry-run] [--ca-password PWD]
```

Renews certificates expiring within N days (default: 7).

| Flag              | Description                                          |
|-------------------|------------------------------------------------------|
| `--within-days N` | Renew certs expiring within N days (default: 7)      |
| `--days N`        | Days for renewed certificate validity (default: 30)  |
| `-f, --force`     | Force renewal even if certificate hasn't expired     |
| `--dry-run`       | Show what would be renewed without making changes    |
| `--ca-password`   | Password for encrypted CA key                        |

### list

```bash
devssl list [--verbose]
```

List all certificates with their expiry dates, domains, and status. Use `--verbose` to show all domains instead of abbreviated list.

### inspect

```bash
devssl inspect <NAME>
```

Show detailed information about a specific certificate, including domains, validity period, and certificate type.

### status

Shows CA and certificate information.

### uninstall

```bash
devssl uninstall [--keep-certs] [--yes]
```

Removes CA from trust store and deletes certificate files.

### path

```bash
devssl path [NAME]
```

Show certificate and CA file paths. If NAME is provided, shows paths for that certificate.

### chain

```bash
devssl chain <NAME> [--output FILE]
```

Export a certificate chain (certificate + CA) to a single file. Useful for servers that need the full chain.

| Flag                | Description                        |
|---------------------|------------------------------------|
| `-o, --output FILE` | Output file path (default: stdout) |

### backup

```bash
devssl backup [--output DIR]
```

Backup CA and all certificates to a directory. Creates a complete snapshot that can be restored later.

| Flag               | Description                                      |
|--------------------|--------------------------------------------------|
| `-o, --output DIR` | Backup directory path (default: `devssl-backup`) |

### restore

```bash
devssl restore <DIR> [--force]
```

Restore CA and certificates from a backup directory.

| Flag      | Description              |
|-----------|--------------------------|
| `--force` | Overwrite existing files |

### trust

```bash
devssl trust install   # Add CA to system trust store
devssl trust remove    # Remove CA from system trust store
devssl trust status    # Check if CA is trusted
```

Manage the system trust store independently. Useful after restoring from backup or fixing trust store issues.

### doctor

```bash
devssl doctor
```

Diagnose trust store and certificate issues. Checks CA validity, trust store status, Firefox NSS, and NODE_EXTRA_CA_CERTS.

### watch

```bash
devssl watch --exec "COMMAND" [--name NAME] [--interval SECS]
```

Watch certificates and restart a command when they change. Useful for development servers that need to reload on cert renewal.

| Flag              | Description                                    |
|-------------------|------------------------------------------------|
| `--exec COMMAND`  | Command to run (required)                      |
| `--name NAME`     | Certificate name to watch (default: localhost) |
| `--interval SECS` | Check interval in seconds (default: 2)         |

### qr

```bash
devssl qr [--save FILE] [--port PORT] [--bind ADDR]
```

Generate QR code for CA certificate installation on mobile devices. Starts a temporary HTTP server to serve the certificate.

| Flag          | Description                                                 |
|---------------|-------------------------------------------------------------|
| `--save FILE` | Save QR code as PNG image instead of displaying in terminal |
| `--port PORT` | Port for temporary HTTP server (default: 8443)              |
| `--bind ADDR` | Address to bind the HTTP server to (default: 0.0.0.0)       |

**Security Note:** The default bind address `0.0.0.0` exposes the CA certificate to your entire network. Use `--bind 127.0.0.1` on untrusted networks.

### nginx / traefik / docker-compose

```bash
devssl nginx [NAME]
devssl traefik [NAME]
devssl docker-compose [NAME]
```

Output configuration snippets for various tools.

### daemon

```bash
devssl daemon start [--on-renew "COMMAND"]
devssl daemon stop
devssl daemon status
devssl daemon run [--on-renew "COMMAND"]
devssl daemon logs [-n LINES] [-f]
```

Manage the auto-renewal daemon. The daemon runs in the background and automatically renews expiring certificates.

| Subcommand | Description                            |
|------------|----------------------------------------|
| `start`    | Start the daemon in background         |
| `stop`     | Stop the running daemon                |
| `status`   | Show daemon status and configuration   |
| `run`      | Run in foreground (for systemd/launchd)|
| `logs`     | Show daemon log output                 |

| Flag                   | Description                                      |
|------------------------|--------------------------------------------------|
| `--on-renew "COMMAND"` | Command to execute when certificates are renewed |
| `-n, --lines N`        | Number of log lines to show (default: 50)        |
| `-f, --follow`         | Follow log output in real-time (like `tail -f`)  |

### Team CA Sharing

```bash
# Export CA for team sharing
devssl export-ca [--include-key] [--output FILE] [--format pem|der]

# Import shared CA
devssl import-ca <FILE> [--trust] [--force]
```

Share CA certificates across a team. Use `--include-key` to allow the recipient to generate new certificates. Use `--force` to import even if the certificate is not a CA.

**Note:** The `--include-key` option is only supported with `--format pem`. DER format does not support bundling the certificate and private key.

### Key Encryption

```bash
# Encrypt an existing CA key
devssl encrypt-key

# Decrypt an encrypted CA key
devssl decrypt-key

# Change password on encrypted key
devssl change-password
```

Protect the CA private key with password encryption.

### Shell Completions

```bash
devssl completions <SHELL>
```

Generate shell completions. Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

## Security

The CA private key can sign certificates for any domain. Keep the devssl data folder secure.

Certificates are only issued for:

- `localhost`, `*.localhost`
- Private IPs (127.x.x.x, 10.x.x.x, 192.168.x.x, etc.)
- Reserved TLDs: `.localhost`, `.local`, `.test`, `.example`, `.invalid`, `.internal`, `.lan`, `.home`, `.corp`, `.intranet`, `.private`, `.devlocal`

Public domains like `.com`, `.org`, `.io` are rejected.

## Requirements

| Platform | Dependencies                                                   |
|----------|----------------------------------------------------------------|
| Linux    | `sudo`, `update-ca-certificates` / `update-ca-trust` / `trust` |
| macOS    | None (uses Keychain)                                           |
| Windows  | None (uses certutil)                                           |

## Configuration

### Config File

Optional `config.toml` in the devssl data directory:

```toml
cert_days = 365
ca_days = 3650

[daemon]
check_interval_hours = 1
renew_within_days = 7
```

Note: `cert_days` is used by `init --days` when no value is specified. The `generate` and `renew` commands default to 30 days.

### Environment Variables

| Variable              | Description                                                              |
|-----------------------|--------------------------------------------------------------------------|
| `DEVSSL_ROOT`         | Custom path for certificate storage (overrides default location)         |
| `DEVSSL_TRUST_STORES` | Comma-separated list of trust stores to use: `system`, `nss`, `java`     |
| `DEVSSL_PASSWORD`     | Password for encrypted CA key operations                                 |
| `DEVSSL_NEW_PASSWORD` | New password when changing CA key password                               |
| `DEVSSL_RENEWED_CERT` | Name of certificate that was renewed (available in `--on-renew` scripts) |
| `SSL_CERT_FILE`       | Standard env var for certificate path (set by `devssl init`)             |
| `SSL_KEY_FILE`        | Standard env var for key path (set by `devssl init`)                     |
| `NODE_EXTRA_CA_CERTS` | Path to CA cert for Node.js applications                                 |

## License

Apache-2.0

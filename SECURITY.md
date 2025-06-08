# Security Policy

## Reporting Vulnerabilities

Use GitHub's private security advisory:
<https://github.com/jayashankarvr/devssl/security/advisories/new>

Do not open public issues for security vulnerabilities.

## Security Model

devssl creates a local CA that signs certificates. The CA private key is stored at `~/.local/share/devssl/ca.key` with 0600 permissions.

**Risk:** A compromised CA key allows creating trusted certificates for any domain.

**Mitigations:**

- No network requests; key stays local
- 30-day certificate validity by default
- Only signs localhost, private IPs, and dev TLDs (`.local`, `.test`, `.internal`, etc.)

## Security Considerations

### Command-Line Password Visibility

The `--ca-password` flag exposes the password in the process list (`ps aux`, `/proc/[pid]/cmdline`). For sensitive environments, use the `DEVSSL_PASSWORD` environment variable instead, or enter the password interactively when prompted.

### Environment Variable Password Visibility

The `DEVSSL_PASSWORD` environment variable is visible in `/proc/[pid]/environ` on Linux. This is an OS limitation. For maximum security, use interactive password entry.

### Daemon `--on-renew` Command

The `--on-renew` flag passes your command directly to the shell. This is intentional to allow arbitrary reload commands, but:

- Never use untrusted input in the command
- The command runs with the daemon's privileges
- Commands are logged to `daemon.log`

### QR Code Server Network Exposure

The `devssl qr` command binds to `0.0.0.0:8443` by default, exposing your CA certificate to the entire network. Use `--bind 127.0.0.1` to restrict access, or ensure you're on a trusted network.

### Trust Store Operations

Adding the CA to system trust stores requires elevated privileges:

- **Linux/macOS:** Uses `sudo` for system-wide trust
- **Windows:** Requires administrator UAC prompt

These operations modify system security settings. Review the trust store locations in your platform's documentation.

### Multi-User Systems

Each user has their own CA in `~/.local/share/devssl/`, but system trust stores are shared. If User B runs `devssl init`, it will overwrite User A's CA in the system trust store. User A's existing certificates will stop working.

**Workarounds:**

- Use a single shared CA for all users (export/import with `devssl export-ca` / `devssl import-ca`)
- Skip system trust store: `DEVSSL_TRUST_STORES=user devssl init`
- Accept browser warnings for other users' certs

## Recommendations

- Enable disk encryption
- Do not share the devssl data folder
- If compromised: `devssl uninstall && devssl init --force`
- Use interactive password entry instead of `--ca-password` in shared environments
- Use `--bind 127.0.0.1` with `devssl qr` on untrusted networks

## Scope

In scope:

- CA key generation
- Certificate signing
- Domain validation bypass
- Trust store operations
- Path traversal

Out of scope:

- Browser warnings before `init` (expected)
- Local privilege escalation (requires sudo by design)

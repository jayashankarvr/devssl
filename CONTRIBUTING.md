# Contributing to devssl

Thank you for your interest in contributing to devssl!

## Quick Start

```bash
git clone https://github.com/jayashankarvr/devssl.git
cd devssl
cargo build
cargo test
```

Requires Rust 1.70+. Trust store tests need sudo (Linux), Keychain access (macOS), or admin rights (Windows).

## Development Workflow

```bash
# Build and run
cargo run -- init --skip-trust-store
cargo run -- generate myapp.local
cargo run -- status

# Before committing
cargo fmt
cargo clippy --all-targets
cargo test
```

## Architecture Overview

### Module Structure

```bash
src/
├── main.rs      # CLI entry point, command definitions (clap)
├── lib.rs       # Library exports
├── ca.rs        # CA certificate generation and management
├── cert.rs      # End-entity certificate generation
├── config.rs    # Configuration file handling and paths
├── daemon.rs    # Auto-renewal daemon
├── error.rs     # Error types
├── fs.rs        # File system utilities, reserved names
├── proxy.rs     # HTTPS reverse proxy server
├── trust/       # Trust store implementations
│   ├── mod.rs   # Trust store trait and detection
│   ├── linux.rs # Linux system trust store
│   ├── macos.rs # macOS Keychain
│   └── windows.rs # Windows certificate store
└── x509.rs      # X.509 certificate parsing and inspection
```

### Key Modules

| Module   | Responsibility                                    |
|----------|---------------------------------------------------|
| `ca`     | Creates and loads the root CA, signs certificates |
| `cert`   | Generates server, client, and S/MIME certificates |
| `trust`  | Platform-specific trust store installation/removal|
| `proxy`  | TLS termination proxy with HTTP redirect          |
| `daemon` | Background certificate renewal service            |
| `config` | TOML config parsing, certificate paths            |

### Data Flow

```md
User runs "devssl init"
    v
main.rs parses CLI (clap)
    v
ca.rs generates CA keypair (rcgen)
    v
trust/ installs CA in system store
    v
cert.rs generates localhost certificate
    v
config.rs saves to ~/.local/share/devssl/
```

## Adding a New Command

1. Add the command variant to `Commands` enum in `main.rs`:

   ```rust
   #[derive(Subcommand)]
   enum Commands {
       // ...
       MyCommand {
           #[arg(long)]
           option: String,
       },
   }
   ```

2. Add the match arm in `run()`:

   ```rust
   Commands::MyCommand { option } => cmd_my_command(&paths, &option),
   ```

3. Implement the command function:

   ```rust
   fn cmd_my_command(paths: &Paths, option: &str) -> Result<()> {
       // Implementation
       Ok(())
   }
   ```

4. Add tests in `tests/cli_tests.rs`

## Adding a New Trust Store

1. Create `src/trust/newplatform.rs`:

   ```rust
   use crate::error::Result;
   use std::path::Path;

   pub fn install(ca_path: &Path) -> Result<()> {
       // Install CA to trust store
   }

   pub fn remove(ca_path: &Path) -> Result<()> {
       // Remove CA from trust store
   }

   pub fn is_trusted(ca_path: &Path) -> Result<bool> {
       // Check if CA is trusted
   }
   ```

2. Add to `src/trust/mod.rs`:

   ```rust
   #[cfg(target_os = "newplatform")]
   mod newplatform;
   ```

3. Update the dispatch functions in `mod.rs`

## Testing Strategy

### Unit Tests

Located in each module with `#[cfg(test)]`:

- Test individual functions in isolation
- No external dependencies
- Run with `cargo test --lib`

### Integration Tests

Located in `tests/cli_tests.rs`:

- Test the full CLI binary
- Use isolated temp directories via `XDG_DATA_HOME`
- Skip trust store operations with `--skip-trust-store`
- Run with `cargo test --test cli_tests`

### Testing Tips

```bash
# Run specific test
cargo test test_init_creates_ca

# Run with output
cargo test -- --nocapture

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test cli_tests
```

## Code Style

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Prefer explicit error handling over `.unwrap()`
- Add doc comments for public functions
- Keep functions focused and small

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the full test suite
6. Open a PR with a clear description

## Bug Reports

Please include:

- Operating system and version
- devssl version (`devssl --version`)
- Rust version if building from source
- Steps to reproduce
- Expected vs actual behavior
- Any error messages or logs

## Questions?

Open an issue or discussion on GitHub.

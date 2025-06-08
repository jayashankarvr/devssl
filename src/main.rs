// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use devssl::{
    change_key_password, daemon, decrypt_existing_key, encrypt_existing_key, get_trust_store,
    is_reserved_name, load_tls_config, run_proxy_with_redirect, Ca, Cert, CertType, Config, Error,
    Paths, RedirectConfig, Result,
};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// ============================================================================
// Helper functions
// ============================================================================

/// Display a confirmation prompt and return true if user confirms with 'y' or 'yes'
fn confirm_prompt(message: &str) -> bool {
    print!("{} [y/N] ", message);
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    input == "y" || input == "yes"
}

/// List all certificates (excluding CA) in the devssl directory
/// Returns a sorted list of (name, path) tuples
fn list_certificates(paths: &Paths) -> Result<Vec<(String, PathBuf)>> {
    let entries = std::fs::read_dir(&paths.base).map_err(|e| Error::ReadDir {
        path: paths.base.clone(),
        source: e,
    })?;

    let mut certs: Vec<_> = Vec::new();
    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                // Log directory entry read errors instead of silently ignoring
                eprintln!(
                    "Warning: Could not read directory entry in {}: {}",
                    paths.base.display(),
                    e
                );
                continue;
            }
        };
        let path = entry.path();
        if path.extension().map(|e| e == "crt").unwrap_or(false) {
            if let Some(stem) = path.file_stem() {
                let name = stem.to_string_lossy().to_string();
                if name != "ca" {
                    certs.push((name, path));
                }
            }
        }
    }

    certs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(certs)
}

/// Prompt for a new password with confirmation
/// Returns the password if both entries match and password is non-empty
fn prompt_new_password() -> Result<String> {
    prompt_password_with_confirm("Enter new password: ", "Confirm new password: ")
}

/// Prompt for a password with custom prompts and confirmation
fn prompt_password_with_confirm(prompt: &str, confirm_prompt: &str) -> Result<String> {
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Config(format!("Failed to read password: {}", e)))?;

    let confirm = rpassword::prompt_password(confirm_prompt)
        .map_err(|e| Error::Config(format!("Failed to read password: {}", e)))?;

    if password != confirm {
        return Err(Error::Config("Passwords do not match".to_string()));
    }

    if password.is_empty() {
        return Err(Error::Config("Password cannot be empty".to_string()));
    }

    Ok(password)
}

// ============================================================================
// CLI definitions
// ============================================================================

#[derive(Parser)]
#[command(name = "devssl")]
#[command(about = "Zero-config local HTTPS for development")]
#[command(version)]
#[command(after_help = "\
EXAMPLES:
    devssl init                    # Set up CA and localhost cert
    devssl proxy 3000              # Proxy HTTPS to localhost:3000
    devssl generate myapp.local    # Cert for custom domain
    devssl status                  # Check CA and certificates

DOCS: https://github.com/jayashankarvr/devssl")]
struct Cli {
    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Show detailed output
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize devssl (generate CA and add to trust store)
    Init {
        /// Regenerate CA even if it exists
        #[arg(long)]
        force: bool,

        /// Skip adding CA to system trust store
        #[arg(long)]
        skip_trust_store: bool,

        /// CI/Docker mode: generate certs without trust store installation
        #[arg(long)]
        ci: bool,

        /// Days until localhost certificate expires (default: 365)
        #[arg(long)]
        days: Option<u32>,

        /// Print NODE_EXTRA_CA_CERTS export command after init
        #[arg(long)]
        node: bool,

        /// Auto-detect framework and show configuration hints
        #[arg(long)]
        detect: bool,

        /// Encrypt the CA private key with a password
        #[arg(long)]
        encrypt: bool,

        /// Password for CA key encryption (for automation; prefer prompt or DEVSSL_PASSWORD env)
        #[arg(long, requires = "encrypt")]
        ca_password: Option<String>,

        /// Trust stores to install CA into (comma-separated: system,nss,java)
        #[arg(long, value_delimiter = ',')]
        trust_stores: Option<Vec<String>>,
    },

    /// Generate certificate for custom domains, S/MIME, or sign a CSR
    Generate {
        /// Domain names to include in the certificate
        #[arg(required_unless_present_any = ["csr", "email"])]
        domains: Vec<String>,

        /// Days until certificate expires
        #[arg(long, default_value = "30", value_parser = clap::value_parser!(u32).range(1..))]
        days: u32,

        /// Output directory for certificate files
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,

        /// Overwrite existing certificate without prompting
        #[arg(long, short)]
        force: bool,

        /// Sign a Certificate Signing Request (CSR) file instead of generating a new key pair
        #[arg(long, conflicts_with = "domains")]
        csr: Option<std::path::PathBuf>,

        /// Export as PKCS12 (.p12) file alongside .crt/.key
        #[arg(long)]
        pkcs12: bool,

        /// Password for PKCS12 file (default: empty)
        #[arg(long, default_value = "")]
        password: String,

        /// Generate client authentication certificate instead of server
        #[arg(long)]
        client: bool,

        /// Email addresses for S/MIME certificate (can be specified multiple times)
        #[arg(long, short = 'e', conflicts_with = "client")]
        email: Vec<String>,

        /// Password for encrypted CA key (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        ca_password: Option<String>,
    },

    /// Show current status
    Status,

    /// List all certificates with expiry info
    List,

    /// Show detailed information about a certificate
    Inspect {
        /// Certificate name to inspect
        name: String,
    },

    /// Remove devssl from system
    Uninstall {
        /// Keep certificate files
        #[arg(long)]
        keep_certs: bool,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Renew expiring certificates
    Renew {
        /// Specific certificate to renew (e.g., "localhost" or "myapp.local")
        #[arg()]
        name: Option<String>,

        /// Renew certificates expiring within N days (default: 7)
        #[arg(long, default_value = "7", value_parser = clap::value_parser!(u32).range(1..))]
        within_days: u32,

        /// Days for renewed certificate validity
        #[arg(long, default_value = "30", value_parser = clap::value_parser!(u32).range(1..))]
        days: u32,

        /// Force renewal even if certificate hasn't expired
        #[arg(long, short)]
        force: bool,

        /// Show what would be renewed without making changes
        #[arg(long)]
        dry_run: bool,

        /// Password for encrypted CA key (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        ca_password: Option<String>,
    },

    /// Start HTTPS proxy server
    Proxy {
        /// Backend address to forward to (PORT or HOST:PORT, e.g., "3000" or "192.168.1.5:3000")
        backend: String,

        /// Certificate hostname (selects which certificate to load, does not change bind address)
        #[arg(long, default_value = "localhost")]
        host: String,

        /// HTTPS port to listen on (defaults to backend port)
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        https_port: Option<u16>,

        /// Also listen on HTTP and redirect to HTTPS
        #[arg(long)]
        redirect: bool,

        /// HTTP port to listen on for redirects (default: 8080)
        #[arg(long, default_value = "8080", value_parser = clap::value_parser!(u16).range(1..))]
        http_port: u16,

        /// Address to bind the proxy to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Password for encrypted CA key (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        ca_password: Option<String>,
    },

    /// Show certificate and CA paths
    Path {
        /// Certificate name to show paths for (e.g., "localhost", "myapp.local")
        name: Option<String>,
    },

    /// Export certificate chain (cert + CA) to a single file
    Chain {
        /// Certificate name to export (e.g., "localhost", "myapp.local")
        name: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Output nginx SSL config snippet
    Nginx {
        /// Certificate name (default: localhost)
        #[arg(default_value = "localhost")]
        name: String,
    },

    /// Output Traefik TLS config
    Traefik {
        /// Certificate name (default: localhost)
        #[arg(default_value = "localhost")]
        name: String,
    },

    /// Output docker-compose.override.yml snippet
    DockerCompose {
        /// Certificate name (default: localhost)
        #[arg(default_value = "localhost")]
        name: String,
    },

    /// Generate QR code for CA certificate installation on mobile devices
    Qr {
        /// Save QR code as PNG image instead of displaying in terminal
        #[arg(long)]
        save: Option<std::path::PathBuf>,

        /// Port for temporary HTTP server (for serving CA cert)
        #[arg(long, default_value = "8443", value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        /// Address to bind the HTTP server to (default: 0.0.0.0 for mobile access)
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
    },

    /// Watch certificates and restart a command when they change
    Watch {
        /// Command to execute (e.g., "npm run dev" or "cargo run")
        #[arg(long)]
        exec: String,

        /// Certificate name to watch (default: localhost)
        #[arg(long)]
        name: Option<String>,

        /// Poll interval in seconds (default: 2)
        #[arg(long, default_value = "2", value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
    },

    /// Diagnose trust store and certificate issues
    Doctor,

    /// Export CA certificate for team sharing
    ExportCa {
        /// Include private key (enables signing new certificates)
        #[arg(long)]
        include_key: bool,

        /// Output file (default: stdout)
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "pem")]
        format: ExportFormat,
    },

    /// Import a shared CA certificate
    ImportCa {
        /// Path to the CA file (PEM or DER format)
        file: std::path::PathBuf,

        /// Also add CA to system trust store
        #[arg(long)]
        trust: bool,

        /// Force import even if certificate is not a CA
        #[arg(long)]
        force: bool,
    },

    /// Encrypt an existing unencrypted CA key
    EncryptKey {
        /// Password for encryption (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        password: Option<String>,
    },

    /// Decrypt an encrypted CA key (removes password protection)
    DecryptKey {
        /// Password for decryption (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        password: Option<String>,
    },

    /// Change the password on an encrypted CA key
    ChangePassword {
        /// Current password (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        old_password: Option<String>,

        /// New password (or use DEVSSL_NEW_PASSWORD env)
        #[arg(long)]
        new_password: Option<String>,
    },

    /// Backup CA and all certificates to a file
    Backup {
        /// Output file path (default: devssl-backup.tar)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Restore CA and certificates from a backup file
    Restore {
        /// Backup file to restore from
        file: std::path::PathBuf,

        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Manage system trust store
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Manage the auto-renewal daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the renewal daemon in background
    Start {
        /// Command to execute when certificates are renewed
        #[arg(long)]
        on_renew: Option<String>,

        /// Password for encrypted CA key (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        ca_password: Option<String>,
    },

    /// Stop the running daemon
    Stop,

    /// Show daemon status
    Status,

    /// Run in foreground (for systemd/launchd)
    Run {
        /// Command to execute when certificates are renewed
        #[arg(long)]
        on_renew: Option<String>,

        /// Password for encrypted CA key (or use DEVSSL_PASSWORD env)
        #[arg(long)]
        ca_password: Option<String>,
    },

    /// Show daemon log output
    Logs {
        /// Number of lines to show (default: 50)
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,

        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Install CA certificate to system trust store
    Install,

    /// Remove CA certificate from system trust store
    Remove,

    /// Show trust store status
    Status,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ExportFormat {
    Pem,
    Der,
}

struct FrameworkInfo {
    name: &'static str,
    config_hint: &'static str,
}

fn detect_framework() -> Option<FrameworkInfo> {
    let cwd = std::env::current_dir().ok()?;
    let package_json = cwd.join("package.json");
    if package_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&package_json) {
            if content.contains("\"next\"") {
                return Some(FrameworkInfo { name: "Next.js", config_hint: "Add to next.config.js:\n\nconst fs = require('fs');\n\nmodule.exports = {\n  devServer: {\n    https: {\n      key: fs.readFileSync(process.env.SSL_KEY_FILE),\n      cert: fs.readFileSync(process.env.SSL_CERT_FILE),\n    },\n  },\n};\n\nOr for Next.js 13+, run with:\n  NODE_EXTRA_CA_CERTS=\"$HOME/.local/share/devssl/ca.crt\" npm run dev -- --experimental-https" });
            }
            if content.contains("\"vite\"") {
                return Some(FrameworkInfo { name: "Vite", config_hint: "Add to vite.config.ts:\n\nimport fs from 'fs';\n\nexport default defineConfig({\n  server: {\n    https: {\n      key: fs.readFileSync(process.env.SSL_KEY_FILE!),\n      cert: fs.readFileSync(process.env.SSL_CERT_FILE!),\n    },\n  },\n});" });
            }
            if content.contains("\"react-scripts\"") {
                return Some(FrameworkInfo { name: "Create React App", config_hint: "Set environment variables in .env:\n\nHTTPS=true\nSSL_CRT_FILE=$HOME/.local/share/devssl/localhost.crt\nSSL_KEY_FILE=$HOME/.local/share/devssl/localhost.key\n\nThen run: npm start" });
            }
            if content.contains("\"express\"") {
                return Some(FrameworkInfo { name: "Express", config_hint: "Use https.createServer in your app:\n\nconst https = require('https');\nconst fs = require('fs');\nconst express = require('express');\n\nconst app = express();\n\nhttps.createServer({\n  key: fs.readFileSync(process.env.SSL_KEY_FILE),\n  cert: fs.readFileSync(process.env.SSL_CERT_FILE),\n}, app).listen(3000);" });
            }
            if content.contains("\"fastify\"") {
                return Some(FrameworkInfo { name: "Fastify", config_hint: "Configure Fastify with HTTPS:\n\nconst fs = require('fs');\nconst fastify = require('fastify')({\n  https: {\n    key: fs.readFileSync(process.env.SSL_KEY_FILE),\n    cert: fs.readFileSync(process.env.SSL_CERT_FILE),\n  }\n});\n\nfastify.listen({ port: 3000 });" });
            }
            if content.contains("\"nuxt\"") {
                return Some(FrameworkInfo { name: "Nuxt", config_hint: "Add to nuxt.config.ts:\n\nimport fs from 'fs';\n\nexport default defineNuxtConfig({\n  devServer: {\n    https: {\n      key: fs.readFileSync(process.env.SSL_KEY_FILE!),\n      cert: fs.readFileSync(process.env.SSL_CERT_FILE!),\n    },\n  },\n});" });
            }
            if content.contains("\"@sveltejs/kit\"") {
                return Some(FrameworkInfo { name: "SvelteKit", config_hint: "Add to vite.config.ts:\n\nimport fs from 'fs';\nimport { sveltekit } from '@sveltejs/kit/vite';\n\nexport default {\n  plugins: [sveltekit()],\n  server: {\n    https: {\n      key: fs.readFileSync(process.env.SSL_KEY_FILE!),\n      cert: fs.readFileSync(process.env.SSL_CERT_FILE!),\n    },\n  },\n};" });
            }
        }
    }
    let cargo_toml = cwd.join("Cargo.toml");
    if cargo_toml.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
            if content.contains("actix-web") {
                return Some(FrameworkInfo { name: "actix-web", config_hint: "Configure actix-web with rustls. See actix-web TLS documentation.\nUse SSL_CERT_FILE and SSL_KEY_FILE environment variables." });
            }
            if content.contains("axum") {
                return Some(FrameworkInfo { name: "axum", config_hint: "Configure axum with axum-server and rustls:\n\nlet config = RustlsConfig::from_pem_file(\n    std::env::var(\"SSL_CERT_FILE\")?,\n    std::env::var(\"SSL_KEY_FILE\")?,\n).await?;" });
            }
            if content.contains("rocket") {
                return Some(FrameworkInfo { name: "Rocket", config_hint: "Add to Rocket.toml:\n\n[default.tls]\ncerts = \"${SSL_CERT_FILE}\"\nkey = \"${SSL_KEY_FILE}\"" });
            }
            if content.contains("warp") {
                return Some(FrameworkInfo { name: "warp", config_hint: "Configure warp with TLS:\n\nwarp::serve(routes)\n    .tls()\n    .cert_path(std::env::var(\"SSL_CERT_FILE\")?)\n    .key_path(std::env::var(\"SSL_KEY_FILE\")?)\n    .run(([127, 0, 0, 1], 443))\n    .await;" });
            }
        }
    }
    let requirements = cwd.join("requirements.txt");
    let pyproject = cwd.join("pyproject.toml");
    let python_content = std::fs::read_to_string(&requirements)
        .ok()
        .or_else(|| std::fs::read_to_string(&pyproject).ok());
    if let Some(content) = python_content {
        if content.contains("django") || content.contains("Django") {
            return Some(FrameworkInfo { name: "Django", config_hint: "Use django-sslserver or the devssl proxy:\n\nOption 1 - django-sslserver:\n  pip install django-sslserver\n  python manage.py runsslserver --certificate $SSL_CERT_FILE --key $SSL_KEY_FILE\n\nOption 2 - devssl proxy:\n  python manage.py runserver 8000\n  devssl proxy 8000" });
        }
        if content.contains("flask") || content.contains("Flask") {
            return Some(FrameworkInfo { name: "Flask", config_hint: "Configure Flask with SSL context:\n\napp.run(\n    ssl_context=(\n        os.environ['SSL_CERT_FILE'],\n        os.environ['SSL_KEY_FILE']\n    )\n)" });
        }
        if content.contains("fastapi") || content.contains("FastAPI") {
            return Some(FrameworkInfo { name: "FastAPI", config_hint: "Run uvicorn with SSL:\n\nuvicorn main:app --ssl-keyfile=$SSL_KEY_FILE --ssl-certfile=$SSL_CERT_FILE" });
        }
    }
    let go_mod = cwd.join("go.mod");
    if go_mod.exists() {
        if let Ok(content) = std::fs::read_to_string(&go_mod) {
            if content.contains("github.com/gin-gonic/gin") {
                return Some(FrameworkInfo { name: "Gin", config_hint: "Configure Gin with TLS:\n\nr := gin.Default()\nr.RunTLS(\":443\", os.Getenv(\"SSL_CERT_FILE\"), os.Getenv(\"SSL_KEY_FILE\"))" });
            }
            if content.contains("github.com/labstack/echo") {
                return Some(FrameworkInfo { name: "Echo", config_hint: "Configure Echo with TLS:\n\ne := echo.New()\ne.StartTLS(\":443\", os.Getenv(\"SSL_CERT_FILE\"), os.Getenv(\"SSL_KEY_FILE\"))" });
            }
            if content.contains("github.com/gofiber/fiber") {
                return Some(FrameworkInfo { name: "Fiber", config_hint: "Configure Fiber with TLS:\n\napp := fiber.New()\napp.ListenTLS(\":443\", os.Getenv(\"SSL_CERT_FILE\"), os.Getenv(\"SSL_KEY_FILE\"))" });
            }
            return Some(FrameworkInfo { name: "Go net/http", config_hint: "Use ListenAndServeTLS:\n\nhttp.ListenAndServeTLS(\":443\",\n    os.Getenv(\"SSL_CERT_FILE\"),\n    os.Getenv(\"SSL_KEY_FILE\"),\n    nil)" });
        }
    }
    let gemfile = cwd.join("Gemfile");
    if gemfile.exists() {
        if let Ok(content) = std::fs::read_to_string(&gemfile) {
            if content.contains("rails") {
                return Some(FrameworkInfo { name: "Ruby on Rails", config_hint: "Use puma with SSL or the devssl proxy:\n\nOption 1 - Puma SSL (config/puma.rb):\n  ssl_bind '127.0.0.1', '3000', {\n    key: ENV['SSL_KEY_FILE'],\n    cert: ENV['SSL_CERT_FILE']\n  }\n\nOption 2 - devssl proxy:\n  rails server -p 3000\n  devssl proxy 3000" });
            }
            if content.contains("sinatra") {
                return Some(FrameworkInfo { name: "Sinatra", config_hint: "Run Sinatra with SSL using WEBrick:\n\nset :server_settings, {\n  SSLEnable: true,\n  SSLCertificate: OpenSSL::X509::Certificate.new(File.read(ENV['SSL_CERT_FILE'])),\n  SSLPrivateKey: OpenSSL::PKey::RSA.new(File.read(ENV['SSL_KEY_FILE']))\n}" });
            }
        }
    }
    None
}

/// Output helper that respects --quiet and --verbose flags.
#[derive(Clone, Copy)]
struct Output {
    quiet: bool,
    verbose: bool,
}

impl Output {
    fn new(quiet: bool, verbose: bool) -> Self {
        Self { quiet, verbose }
    }

    /// Print a standard message (suppressed with --quiet)
    fn print(&self, msg: &str) {
        if !self.quiet {
            println!("{}", msg);
        }
    }

    /// Print a verbose message (only shown with --verbose)
    fn verbose(&self, msg: &str) {
        if self.verbose {
            println!("{}", msg);
        }
    }
}

fn main() {
    // Reset SIGPIPE to default behavior (exit) instead of panic
    // This prevents "broken pipe" panics when output is piped to tools like grep/head
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::new()?;
    let out = Output::new(cli.quiet, cli.verbose);

    // Check for expiring certificates and warn the user (skip in quiet mode)
    if !cli.quiet {
        check_expiring_certificates(&paths);
    }

    match cli.command {
        Commands::Init {
            force,
            skip_trust_store,
            ci,
            days,
            node,
            detect,
            encrypt,
            ca_password,
            trust_stores,
        } => cmd_init(
            &paths,
            force,
            skip_trust_store,
            ci,
            days,
            node,
            detect,
            encrypt,
            ca_password,
            trust_stores,
            out,
        ),
        Commands::Generate {
            domains,
            days,
            output,
            force,
            csr,
            pkcs12,
            password,
            client,
            email,
            ca_password,
        } => cmd_generate(
            &paths,
            &domains,
            days,
            output.as_deref(),
            force,
            csr.as_deref(),
            pkcs12,
            &password,
            client,
            &email,
            ca_password,
        ),
        Commands::Status => cmd_status(&paths),
        Commands::List => cmd_list(&paths),
        Commands::Inspect { name } => cmd_inspect(&paths, &name),
        Commands::Uninstall { keep_certs, yes } => cmd_uninstall(&paths, keep_certs, yes),
        Commands::Renew {
            name,
            within_days,
            days,
            force,
            dry_run,
            ca_password,
        } => cmd_renew(
            &paths,
            name.as_deref(),
            within_days,
            days,
            force,
            dry_run,
            ca_password,
            out,
        ),
        Commands::Proxy {
            backend,
            host,
            https_port,
            redirect,
            http_port,
            bind,
            ca_password,
        } => cmd_proxy(
            &paths,
            ProxyConfig {
                backend: &backend,
                host: &host,
                https_port,
                redirect,
                http_port,
                bind: &bind,
            },
            ca_password,
        ),
        Commands::Path { name } => cmd_path(&paths, name.as_deref()),
        Commands::Chain { name, output } => cmd_chain(&paths, &name, output.as_deref()),
        Commands::Nginx { name } => cmd_nginx(&paths, &name),
        Commands::Traefik { name } => cmd_traefik(&paths, &name),
        Commands::DockerCompose { name } => cmd_docker_compose(&paths, &name),
        Commands::Qr { save, port, bind } => cmd_qr(&paths, save.as_deref(), port, &bind),
        Commands::Watch {
            exec,
            name,
            interval,
        } => cmd_watch(&paths, &exec, name.as_deref(), interval),
        Commands::Doctor => cmd_doctor(&paths),
        Commands::ExportCa {
            include_key,
            output,
            format,
        } => cmd_export_ca(&paths, include_key, output.as_deref(), format),
        Commands::ImportCa { file, trust, force } => cmd_import_ca(&paths, &file, trust, force),
        Commands::EncryptKey { password } => cmd_encrypt_key(&paths, password),
        Commands::DecryptKey { password } => cmd_decrypt_key(&paths, password),
        Commands::ChangePassword {
            old_password,
            new_password,
        } => cmd_change_password(&paths, old_password, new_password),
        Commands::Backup { output } => cmd_backup(&paths, output),
        Commands::Restore { file, force } => cmd_restore(&paths, &file, force),
        Commands::Trust { action } => cmd_trust(&paths, action),
        Commands::Daemon { action } => cmd_daemon(&paths, action),
        Commands::Completions { shell } => cmd_completions(shell),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_init(
    paths: &Paths,
    force: bool,
    skip_trust_store: bool,
    ci: bool,
    days: Option<u32>,
    node: bool,
    detect: bool,
    encrypt: bool,
    ca_password: Option<String>,
    trust_stores: Option<Vec<String>>,
    out: Output,
) -> Result<()> {
    let config = Config::load(&paths.config)?;

    // Use provided days or config default
    let cert_days = days.unwrap_or(config.cert_days);

    // Check if already initialized
    if paths.ca_exists() && !force {
        return Err(Error::CaAlreadyExists(paths.ca_cert.clone()));
    }

    out.print("Initializing devssl...");

    // Set trust stores filter if specified via CLI
    if let Some(stores) = &trust_stores {
        std::env::set_var("DEVSSL_TRUST_STORES", stores.join(","));
    }

    // Get password for encryption if requested
    let password = if encrypt {
        Some(get_password(
            ca_password,
            "DEVSSL_PASSWORD",
            "Enter CA key password: ",
        )?)
    } else {
        None
    };

    // Generate CA
    out.print("  Generating CA...");
    let ca = Ca::generate(config.ca_days)?;
    ca.save_with_password(paths, password.as_deref())?;
    out.verbose(&format!("  CA saved to {}", paths.ca_cert.display()));

    // Add to trust store (unless skipped or in CI mode)
    if ci {
        out.print("  Skipping trust store (--ci mode)");
    } else if skip_trust_store {
        out.print("  Skipping trust store (--skip-trust-store)");
    } else {
        out.print("  Adding CA to trust store...");
        let trust = get_trust_store();
        trust.add_ca(&paths.ca_cert)?;
        out.verbose(&format!("  Added to {}", trust.name()));
    }

    // Generate localhost certificate
    out.print("  Generating localhost certificate...");
    let result = Cert::generate_localhost(&ca, cert_days)?;
    if let Some(warning) = &result.warning {
        eprintln!("  Warning: {}", warning);
    }
    result.cert.save(paths, "localhost")?;

    let cert_path = paths.cert_path("localhost")?;
    if let Some((expiry, days_left)) = get_cert_info(&cert_path) {
        out.verbose(&format!(
            "  Certificate saved to {} (expires: {}, {} days)",
            cert_path.display(),
            expiry,
            days_left
        ));
    } else {
        out.verbose(&format!("  Certificate saved to {}", cert_path.display()));
    }

    // Save default config
    config.save(&paths.config)?;

    out.print("");
    out.print("Done! devssl is ready to use.");
    out.print("");
    println!("Certificate: {}", paths.cert_path("localhost")?.display());
    println!("Private key: {}", paths.key_path("localhost")?.display());
    println!();
    println!("Or use environment variables:");
    println!(
        "  export SSL_CERT_FILE={}",
        paths.cert_path("localhost")?.display()
    );
    println!(
        "  export SSL_KEY_FILE={}",
        paths.key_path("localhost")?.display()
    );

    // Print Node.js export command if --node flag is set
    if node {
        println!();
        println!("For Node.js:");
        println!(
            "  export NODE_EXTRA_CA_CERTS=\"{}\"",
            paths.ca_cert.display()
        );
    }

    // Detect framework and print configuration hints if --detect flag is set
    if detect {
        println!();
        if let Some(framework) = detect_framework() {
            println!("Detected framework: {}", framework.name);
            println!();
            println!("Configuration hint:");
            println!("{}", framework.config_hint);
        } else {
            println!("No framework detected in current directory.");
            println!();
            println!("Generic usage:");
            println!("  Certificate: {}", paths.cert_path("localhost")?.display());
            println!("  Private key: {}", paths.key_path("localhost")?.display());
            println!();
            println!("Or use the devssl proxy:");
            println!("  devssl proxy <backend>  (e.g., 3000 or 192.168.1.5:3000)");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_generate(
    paths: &Paths,
    domains: &[String],
    days: u32,
    output: Option<&std::path::Path>,
    force: bool,
    csr_path: Option<&std::path::Path>,
    pkcs12: bool,
    password: &str,
    client: bool,
    emails: &[String],
    ca_password: Option<String>,
) -> Result<()> {
    let ca = load_ca_with_password(paths, ca_password)?;

    // Handle CSR signing mode
    if let Some(csr_file) = csr_path {
        // Warn if flags are used that will be ignored
        if client {
            eprintln!("Warning: --client flag is ignored when signing a CSR");
        }
        if !emails.is_empty() {
            eprintln!("Warning: --email flag is ignored when signing a CSR");
        }
        return cmd_generate_from_csr(&ca, csr_file, days, output, force);
    }

    // Determine the certificate name based on what's provided
    let name = if !emails.is_empty() {
        // For S/MIME certs, use first email (sanitize for filename)
        // Replace characters that are problematic in filenames
        emails
            .first()
            .map(|e| {
                e.replace('@', "_at_")
                    .replace('.', "_")
                    .replace('+', "_plus_")
                    .replace([' ', '/', '\\'], "_")
            })
            .unwrap_or_else(|| "smime".into())
    } else {
        // Use first domain as filename
        domains
            .first()
            .map(|d| d.replace('*', "_wildcard_"))
            .unwrap_or_else(|| "cert".into())
    };

    // Check for reserved names
    if is_reserved_name(&name) {
        return Err(Error::ReservedName(name));
    }

    // Check if certificate already exists
    let cert_path = if let Some(out_dir) = output {
        out_dir.join(format!("{}.crt", name))
    } else {
        paths.cert_path(&name)?
    };

    if cert_path.exists() && !force {
        return Err(Error::Config(format!(
            "Certificate already exists: {}\nUse --force to overwrite.",
            cert_path.display()
        )));
    }

    // Generate the appropriate certificate type
    let result = if !emails.is_empty() {
        // S/MIME certificate
        if domains.is_empty() {
            println!("Generating S/MIME certificate for: {}", emails.join(", "));
        } else {
            println!(
                "Generating S/MIME certificate for: {} (with domains: {})",
                emails.join(", "),
                domains.join(", ")
            );
        }
        Cert::generate_smime(&ca, emails, domains, days)?
    } else if client {
        println!("Generating client certificate for: {}", domains.join(", "));
        Cert::generate_client(&ca, domains, days)?
    } else {
        println!("Generating server certificate for: {}", domains.join(", "));
        Cert::generate(&ca, domains, days)?
    };
    if let Some(warning) = &result.warning {
        eprintln!("Warning: {}", warning);
    }
    let cert = result.cert;

    // Determine output paths
    let (cert_path, key_path) = if let Some(out_dir) = output {
        // Create output directory if it doesn't exist
        if !out_dir.exists() {
            std::fs::create_dir_all(out_dir).map_err(|e| Error::CreateDir {
                path: out_dir.to_path_buf(),
                source: e,
            })?;
        }
        (
            out_dir.join(format!("{}.crt", name)),
            out_dir.join(format!("{}.key", name)),
        )
    } else {
        (paths.cert_path(&name)?, paths.key_path(&name)?)
    };

    // Save certificate
    std::fs::write(&cert_path, &cert.pem).map_err(|e| Error::WriteFile {
        path: cert_path.clone(),
        source: e,
    })?;

    // Save key with restricted permissions
    devssl::write_secret_file(&key_path, cert.key_pem.as_bytes())?;

    // Show output with expiry
    if let Some((expiry, days_remaining)) = get_cert_info(&cert_path) {
        println!(
            "Certificate: {} (expires: {}, {} days)",
            cert_path.display(),
            expiry,
            days_remaining
        );
    } else {
        println!("Certificate: {}", cert_path.display());
    }
    println!("Private key: {}", key_path.display());

    // Export as PKCS12 if requested
    if pkcs12 {
        let p12_path = if let Some(out_dir) = output {
            out_dir.join(format!("{}.p12", name))
        } else {
            paths.base.join(format!("{}.p12", name))
        };

        cert.export_pkcs12(&p12_path, password)?;
        println!("PKCS12:      {}", p12_path.display());
    }

    Ok(())
}

fn cmd_generate_from_csr(
    ca: &Ca,
    csr_path: &std::path::Path,
    days: u32,
    output: Option<&std::path::Path>,
    force: bool,
) -> Result<()> {
    // Derive output name from CSR filename
    let name = csr_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("cert")
        .to_string();

    // Check for reserved names to prevent overwriting CA files
    if is_reserved_name(&name) {
        return Err(Error::ReservedName(name));
    }

    // Determine output path for certificate
    let cert_path = if let Some(out_dir) = output {
        out_dir.join(format!("{}.crt", name))
    } else {
        // Default to same directory as CSR
        csr_path.with_extension("crt")
    };

    if cert_path.exists() && !force {
        return Err(Error::Config(format!(
            "Certificate already exists: {}\nUse --force to overwrite.",
            cert_path.display()
        )));
    }

    println!("Signing CSR: {}", csr_path.display());

    let result = devssl::Cert::sign_csr(ca, csr_path, days)?;
    if let Some(warning) = &result.warning {
        eprintln!("Warning: {}", warning);
    }

    // Create output directory if needed
    if let Some(out_dir) = output {
        if !out_dir.exists() {
            std::fs::create_dir_all(out_dir).map_err(|e| Error::CreateDir {
                path: out_dir.to_path_buf(),
                source: e,
            })?;
        }
    }

    // Save certificate (no key since requestor has their own)
    std::fs::write(&cert_path, &result.cert_pem).map_err(|e| Error::WriteFile {
        path: cert_path.clone(),
        source: e,
    })?;

    // Show output with expiry
    if let Some((expiry, days_remaining)) = get_cert_info(&cert_path) {
        println!(
            "Certificate: {} (expires: {}, {} days)",
            cert_path.display(),
            expiry,
            days_remaining
        );
    } else {
        println!("Certificate: {}", cert_path.display());
    }

    Ok(())
}

fn cmd_status(paths: &Paths) -> Result<()> {
    println!("devssl status");
    println!("==============");
    println!();

    // Check CA
    print!("CA: ");
    if paths.ca_exists() {
        println!("initialized");
        println!("    Path: {}", paths.ca_cert.display());

        // Show CA expiry
        if let Some((expiry, days)) = get_cert_info(&paths.ca_cert) {
            println!("    Expires: {} ({} days)", expiry, days);
        }

        // Check trust store
        let trust = get_trust_store();
        match trust.is_trusted(&paths.ca_cert) {
            Ok(true) => println!("    Trust store: {} (trusted)", trust.name()),
            Ok(false) => println!("    Trust store: {} (NOT trusted)", trust.name()),
            Err(_) => println!("    Trust store: unknown"),
        }
    } else {
        println!("not initialized");
        println!("    Run 'devssl init' to set up");
        return Ok(());
    }

    println!();

    // List certificates
    println!("Certificates:");
    let certs = list_certificates(paths)?;

    if certs.is_empty() {
        println!("    (none)");
    } else {
        for (name, path) in certs {
            if let Some((expiry, days)) = get_cert_info(&path) {
                println!("    {}.crt (expires: {}, {} days)", name, expiry, days);
            } else {
                println!("    {}.crt", name);
            }
        }
    }

    Ok(())
}

/// Get certificate info (expiry string and days remaining)
fn get_cert_info(cert_path: &std::path::Path) -> Option<(String, i64)> {
    devssl::parse_cert_file(cert_path)
        .ok()
        .map(|info| (info.expiry_string(), info.days_remaining()))
}

/// Check for certificates expiring soon and print a warning.
/// Called at startup to alert users before their certs break.
const EXPIRY_WARNING_DAYS: i64 = 7;

fn check_expiring_certificates(paths: &Paths) {
    // Only check if CA is initialized
    if !paths.ca_exists() {
        return;
    }

    let certs = match list_certificates(paths) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut expiring: Vec<(String, i64)> = Vec::new();
    let mut expired: Vec<String> = Vec::new();

    for (name, path) in certs {
        if let Ok(info) = devssl::parse_cert_file(&path) {
            let days = info.days_remaining();
            if days < 0 {
                expired.push(name);
            } else if days <= EXPIRY_WARNING_DAYS {
                expiring.push((name, days));
            }
        }
    }

    // Also check CA certificate
    if let Ok(ca_info) = devssl::parse_cert_file(&paths.ca_cert) {
        let days = ca_info.days_remaining();
        if days < 0 {
            expired.push("CA".to_string());
        } else if days <= EXPIRY_WARNING_DAYS {
            expiring.push(("CA".to_string(), days));
        }
    }

    if !expired.is_empty() {
        eprintln!(
            "\x1b[31m⚠ EXPIRED certificates: {}\x1b[0m",
            expired.join(", ")
        );
        eprintln!("  Run 'devssl renew' to renew them.\n");
    }

    if !expiring.is_empty() {
        let warnings: Vec<String> = expiring
            .iter()
            .map(|(name, days)| format!("{} ({}d)", name, days))
            .collect();
        eprintln!(
            "\x1b[33m⚠ Certificates expiring soon: {}\x1b[0m",
            warnings.join(", ")
        );
        eprintln!("  Run 'devssl renew' to renew them.\n");
    }
}

fn cmd_list(paths: &Paths) -> Result<()> {
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    let certs = list_certificates(paths)?;

    if certs.is_empty() {
        println!("No certificates found.");
        println!("Run 'devssl generate <domain>' to create one.");
        return Ok(());
    }

    println!("{:<20} {:<12} {:>8}  TYPE", "NAME", "EXPIRES", "DAYS");
    println!("{}", "-".repeat(55));

    for (name, path) in certs {
        let info = devssl::parse_cert_file(&path).ok();
        let expiry = info
            .as_ref()
            .map(|i| i.expiry_string())
            .unwrap_or_else(|| "???".into());
        let days = info.as_ref().map(|i| i.days_remaining()).unwrap_or(-999);
        let cert_type = info
            .as_ref()
            .map(|i| match i.cert_type {
                devssl::CertType::Server => "server",
                devssl::CertType::Client => "client",
                devssl::CertType::Smime => "s/mime",
                devssl::CertType::Unknown => "unknown",
            })
            .unwrap_or("???");

        let days_str = if days < 0 {
            format!("{} (EXPIRED)", days)
        } else if days <= 7 {
            format!("{} (expiring)", days)
        } else {
            days.to_string()
        };

        println!("{:<20} {:<12} {:>8}  {}", name, expiry, days_str, cert_type);
    }

    Ok(())
}

fn cmd_inspect(paths: &Paths, name: &str) -> Result<()> {
    // Use ensure_cert_exists for consistent error handling
    let cert_path = paths.ensure_cert_exists(name)?;

    let info = devssl::parse_cert_file(&cert_path)?;

    println!("Certificate: {}", name);
    println!("===========");
    println!();
    println!("File:       {}", cert_path.display());
    println!("Key:        {}", paths.key_path(name)?.display());
    println!();

    // Type
    let cert_type = match info.cert_type {
        devssl::CertType::Server => "TLS Server (serverAuth)",
        devssl::CertType::Client => "TLS Client (clientAuth)",
        devssl::CertType::Smime => "S/MIME (emailProtection)",
        devssl::CertType::Unknown => "Unknown",
    };
    println!("Type:       {}", cert_type);

    // Common Name
    if let Some(cn) = &info.common_name {
        println!("Common Name: {}", cn);
    }

    // Subject Alternative Names
    if !info.subject_alt_names.is_empty() {
        println!("SANs:");
        for san in &info.subject_alt_names {
            println!("    - {}", san);
        }
    }

    // Email addresses (for S/MIME)
    if !info.emails.is_empty() {
        println!("Emails:");
        for email in &info.emails {
            println!("    - {}", email);
        }
    }

    println!();

    // Validity
    let days = info.days_remaining();
    let expiry = info.expiry_string();
    if days < 0 {
        println!("Status:     EXPIRED ({} days ago)", -days);
    } else if days <= 7 {
        println!("Status:     Expiring soon ({} days)", days);
    } else {
        println!("Status:     Valid ({} days remaining)", days);
    }
    println!("Expires:    {}", expiry);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_renew(
    paths: &Paths,
    name: Option<&str>,
    within_days: u32,
    days: u32,
    force: bool,
    dry_run: bool,
    ca_password: Option<String>,
    out: Output,
) -> Result<()> {
    if dry_run {
        out.print("Dry run mode - no changes will be made.");
        out.print("");
    }

    // Load CA - required for renewing certificates (skip in dry-run)
    let ca = if dry_run {
        None
    } else {
        Some(load_ca_with_password(paths, ca_password)?)
    };

    let mut renewed_count = 0;

    // When force is set, treat within_days as unlimited
    let effective_within_days = if force { u32::MAX } else { within_days };

    if let Some(cert_name) = name {
        // Renew a specific certificate
        let cert_path = paths.cert_path(cert_name)?;

        // Check if cert exists by trying to get metadata - this preserves the actual error
        match std::fs::metadata(&cert_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ReadFile {
                    path: cert_path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Certificate '{}' not found", cert_name),
                    ),
                });
            }
            Err(e) => {
                return Err(Error::ReadFile {
                    path: cert_path,
                    source: e,
                });
            }
        }

        renewed_count += renew_cert_if_expiring(
            paths,
            ca.as_ref(),
            cert_name,
            effective_within_days,
            days,
            true,
            dry_run,
            out,
        )?;
    } else {
        // Scan all .crt files in the devssl directory
        let certs = list_certificates(paths)?;

        if certs.is_empty() {
            out.print("No certificates found to renew.");
            return Ok(());
        }

        if force {
            out.print(&format!("Force renewing {} certificate(s)...", certs.len()));
        } else {
            out.print(&format!(
                "Checking {} certificate(s) for expiration within {} days...",
                certs.len(),
                within_days
            ));
        }

        for (cert_name, _) in &certs {
            renewed_count += renew_cert_if_expiring(
                paths,
                ca.as_ref(),
                cert_name,
                effective_within_days,
                days,
                false,
                dry_run,
                out,
            )?;
        }
    }

    if renewed_count == 0 {
        out.print("No certificates needed renewal.");
    } else if dry_run {
        out.print(&format!(
            "\nWould renew {} certificate(s) with {} day validity.",
            renewed_count, days
        ));
    } else {
        out.print(&format!(
            "\nRenewed {} certificate(s) with {} day validity.",
            renewed_count, days
        ));
    }

    Ok(())
}

/// Renew a certificate if it expires within the specified days
/// Returns 1 if renewed, 0 if not
/// If `verbose` is true, prints a message even when the cert doesn't need renewal
#[allow(clippy::too_many_arguments)]
fn renew_cert_if_expiring(
    paths: &Paths,
    ca: Option<&Ca>,
    name: &str,
    within_days: u32,
    new_days: u32,
    verbose: bool,
    dry_run: bool,
    out: Output,
) -> Result<u32> {
    let cert_path = paths.cert_path(name)?;

    // Parse certificate to check expiry and get domains
    let cert_info = devssl::parse_cert_file(&cert_path)?;
    let days_remaining = cert_info.days_remaining();

    if days_remaining > within_days as i64 {
        // Only print skip message when renewing a specific cert (verbose mode)
        if verbose {
            out.print(&format!(
                "  {}.crt: {} days remaining (not expiring within {} days)",
                name, days_remaining, within_days
            ));
        }
        return Ok(0);
    }

    // Get domains and emails from existing certificate
    let domains: Vec<String> = if cert_info.subject_alt_names.is_empty() {
        // Fallback to common name if no SANs
        cert_info
            .common_name
            .clone()
            .map(|cn| vec![cn])
            .unwrap_or_default()
    } else {
        cert_info.subject_alt_names.clone()
    };
    let emails = cert_info.emails.clone();
    let cert_type = cert_info.cert_type;

    // For S/MIME certs, we need emails; for others, we need domains
    let has_identifiers = match cert_type {
        CertType::Smime => !emails.is_empty(),
        _ => !domains.is_empty(),
    };

    if !has_identifiers {
        eprintln!(
            "Warning: Could not extract identifiers from {}, skipping",
            cert_path.display()
        );
        return Ok(0);
    }

    // Generate new certificate with same type and identifiers
    let status = if days_remaining < 0 {
        "expired"
    } else {
        "expiring"
    };

    let type_str = match cert_type {
        CertType::Server => "server",
        CertType::Client => "client",
        CertType::Smime => "S/MIME",
        CertType::Unknown => "unknown",
    };

    let identifiers = match cert_type {
        CertType::Smime => emails.join(", "),
        _ => domains.join(", "),
    };

    if dry_run {
        out.print(&format!(
            "Would renew {}.crt ({} {}, {} days remaining) for: {}",
            name, type_str, status, days_remaining, identifiers
        ));
        return Ok(1);
    }

    out.print(&format!(
        "Renewing {}.crt ({} {}, {} days remaining) for: {}",
        name, type_str, status, days_remaining, identifiers
    ));

    // CA is required for actual renewal
    let ca = ca.ok_or(Error::CaNotInitialized)?;

    // Generate the appropriate certificate type
    let result = match cert_type {
        CertType::Client => Cert::generate_client(ca, &domains, new_days)?,
        CertType::Smime => Cert::generate_smime(ca, &emails, &domains, new_days)?,
        // Default to server cert for Server and Unknown types
        CertType::Server | CertType::Unknown => Cert::generate(ca, &domains, new_days)?,
    };

    if let Some(warning) = &result.warning {
        eprintln!("  Warning: {}", warning);
    }
    result.cert.save(paths, name)?;

    Ok(1)
}

fn cmd_uninstall(paths: &Paths, keep_certs: bool, yes: bool) -> Result<()> {
    // Prompt for confirmation unless --yes is passed
    if !yes {
        println!("This will:");
        println!("  - Remove CA from system trust store");
        if !keep_certs {
            println!("  - Delete all certificates in {}", paths.base.display());
        }
        println!();

        if !confirm_prompt("Continue?") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Uninstalling devssl...");

    // Remove from trust store
    if paths.ca_exists() {
        println!("  Removing CA from trust store...");
        let trust = get_trust_store();
        if let Err(e) = trust.remove_ca(&paths.ca_cert) {
            eprintln!("  Warning: {}", e);
        }
    }

    // Remove files
    if !keep_certs {
        println!("  Removing certificate files...");
        if paths.base.exists() {
            std::fs::remove_dir_all(&paths.base).map_err(|e| Error::Remove {
                path: paths.base.clone(),
                source: e,
            })?;
        }
    }

    println!("Done!");

    Ok(())
}

fn cmd_path(paths: &Paths, name: Option<&str>) -> Result<()> {
    if let Some(cert_name) = name {
        // Show paths for a specific certificate
        println!("Cert: {}", paths.cert_path(cert_name)?.display());
        println!("Key:  {}", paths.key_path(cert_name)?.display());
    } else {
        // Show CA paths
        println!("CA root: {}", paths.base.display());
        println!("CA cert: {}", paths.ca_cert.display());
        println!("CA key:  {}", paths.ca_key.display());
    }
    Ok(())
}

fn cmd_chain(paths: &Paths, name: &str, output: Option<&std::path::Path>) -> Result<()> {
    let cert_path = paths.cert_path(name)?;

    // Read the certificate
    let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Config(format!(
                "Certificate '{}' not found. Run 'devssl generate {}' first.",
                name, name
            ))
        } else {
            Error::ReadFile {
                path: cert_path.clone(),
                source: e,
            }
        }
    })?;

    // Read the CA certificate
    let ca_pem = std::fs::read_to_string(&paths.ca_cert).map_err(|e| Error::ReadFile {
        path: paths.ca_cert.clone(),
        source: e,
    })?;

    // Combine: cert first, then CA (standard chain order)
    let chain = format!("{}\n{}", cert_pem.trim_end(), ca_pem.trim_end());

    if let Some(out_path) = output {
        std::fs::write(out_path, &chain).map_err(|e| Error::WriteFile {
            path: out_path.to_path_buf(),
            source: e,
        })?;
        eprintln!("Chain written to {}", out_path.display());
    } else {
        print!("{}", chain);
    }

    Ok(())
}

/// Configuration for the proxy command
struct ProxyConfig<'a> {
    backend: &'a str,
    host: &'a str,
    https_port: Option<u16>,
    redirect: bool,
    http_port: u16,
    bind: &'a str,
}

fn cmd_proxy(paths: &Paths, config: ProxyConfig, ca_password: Option<String>) -> Result<()> {
    let (backend_addr, backend_port) = parse_backend_address(config.backend)?;

    fn parse_backend_address(backend: &str) -> Result<(String, u16)> {
        // Check if it's just a port number
        if let Ok(port) = backend.parse::<u16>() {
            if port == 0 {
                return Err(Error::Config("Port cannot be 0".to_string()));
            }
            return Ok((format!("localhost:{}", port), port));
        }

        // Check for IPv6 with brackets: [::1]:8080
        if backend.starts_with('[') {
            if let Some(bracket_end) = backend.find(']') {
                let ipv6 = &backend[1..bracket_end];
                let rest = &backend[bracket_end + 1..];
                if let Some(port_str) = rest.strip_prefix(':') {
                    let port: u16 = port_str.parse().map_err(|_| Error::InvalidPort {
                        port: port_str.to_string(),
                    })?;
                    if port == 0 {
                        return Err(Error::Config("Port cannot be 0".to_string()));
                    }
                    return Ok((format!("[{}]:{}", ipv6, port), port));
                }
            }
            return Err(Error::Config(format!(
                "Invalid IPv6 address format: {}. Use [IPv6]:PORT format",
                backend
            )));
        }

        // Check for IPv6 without brackets (bare ::1 or similar)
        // Count colons - IPv6 has multiple colons
        let colon_count = backend.chars().filter(|&c| c == ':').count();
        if colon_count > 1 {
            // Likely bare IPv6 address without port - not supported
            return Err(Error::Config(format!(
                "IPv6 addresses must use bracket notation: [{}]:PORT",
                backend
            )));
        }

        // Standard HOST:PORT format
        if let Some(colon_pos) = backend.rfind(':') {
            let _host = &backend[..colon_pos];
            let port_str = &backend[colon_pos + 1..];
            let port: u16 = port_str.parse().map_err(|_| Error::InvalidPort {
                port: port_str.to_string(),
            })?;
            if port == 0 {
                return Err(Error::Config("Port cannot be 0".to_string()));
            }
            return Ok((backend.to_string(), port));
        }

        // No colon and not a number - invalid
        Err(Error::Config(format!(
            "Invalid backend address '{}': expected PORT or HOST:PORT",
            backend
        )))
    }

    // Determine which certificate to use based on host
    let cert_name =
        if config.host == "localhost" || config.host == "127.0.0.1" || config.host == "::1" {
            "localhost".to_string()
        } else {
            // For custom hosts, use the host as cert name (e.g., myapp.local)
            config.host.to_string()
        };

    // Use ensure_cert_exists for consistent error handling
    let cert_path = paths.ensure_cert_exists(&cert_name)?;
    let key_path = paths.key_path(&cert_name)?;

    if !key_path.exists() {
        if !paths.ca_exists() {
            return Err(Error::CaNotInitialized);
        }

        let ca = load_ca_with_password(paths, ca_password)?;
        let app_config = Config::load(&paths.config)?;

        if cert_name == "localhost" {
            // Generate localhost cert with standard domains
            println!("Localhost certificate not found. Generating...");
            let result = Cert::generate_localhost(&ca, app_config.cert_days)?;
            if let Some(warning) = &result.warning {
                eprintln!("  Warning: {}", warning);
            }
            result.cert.save(paths, "localhost")?;
            println!("  Generated localhost certificate.");
        } else {
            // Generate cert for custom host
            println!("Certificate for {} not found. Generating...", config.host);
            let result = Cert::generate(&ca, &[config.host.to_string()], app_config.cert_days)?;
            if let Some(warning) = &result.warning {
                eprintln!("  Warning: {}", warning);
            }
            result.cert.save(paths, &cert_name)?;
            println!("  Generated certificate for {}.", config.host);
        }
    }

    // Determine listen address
    // If backend is port 80, default HTTPS to 443; otherwise use same port as backend
    let listen_port = config.https_port.unwrap_or(if backend_port == 80 {
        443
    } else {
        backend_port
    });
    let listen_addr: SocketAddr = format!("{}:{}", config.bind, listen_port)
        .parse()
        .map_err(|e| Error::Config(format!("Invalid bind address '{}': {}", config.bind, e)))?;

    // Set up redirect config if enabled
    let redirect_config = if config.redirect {
        Some(RedirectConfig {
            http_port: config.http_port,
            https_port: listen_port,
            host: config.host.to_string(),
            bind: config.bind.to_string(),
        })
    } else {
        None
    };

    // Run the proxy server
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::Config(format!("Failed to create runtime: {}", e)))?;

    runtime.block_on(async {
        // Load TLS config asynchronously
        println!("Loading TLS configuration...");
        let tls_config = load_tls_config(&cert_path, &key_path).await?;

        run_proxy_with_redirect(listen_addr, backend_addr, tls_config, redirect_config).await
    })
}

fn cmd_nginx(paths: &Paths, name: &str) -> Result<()> {
    // Use ensure_cert_exists for consistent error handling
    let cert_path = paths.ensure_cert_exists(name)?;
    let key_path = paths.ensure_key_exists(name)?;

    println!("ssl_certificate {};", cert_path.display());
    println!("ssl_certificate_key {};", key_path.display());
    println!("ssl_protocols TLSv1.2 TLSv1.3;");

    Ok(())
}

fn cmd_traefik(paths: &Paths, name: &str) -> Result<()> {
    // Verify certificate files exist
    let cert_path = paths.ensure_cert_exists(name)?;
    let key_path = paths.ensure_key_exists(name)?;

    println!("tls:");
    println!("  certificates:");
    println!("    - certFile: {}", cert_path.display());
    println!("      keyFile: {}", key_path.display());

    Ok(())
}

fn cmd_docker_compose(paths: &Paths, name: &str) -> Result<()> {
    // Verify certificate files exist
    let cert_path = paths.ensure_cert_exists(name)?;
    let key_path = paths.ensure_key_exists(name)?;

    println!("services:");
    println!("  app:");
    println!("    volumes:");
    println!(
        "      - {}:/etc/ssl/certs/{}.crt:ro",
        cert_path.display(),
        name
    );
    println!(
        "      - {}:/etc/ssl/private/{}.key:ro",
        key_path.display(),
        name
    );

    Ok(())
}
fn cmd_watch(paths: &Paths, exec: &str, name: Option<&str>, interval_secs: u64) -> Result<()> {
    let cert_name = name.unwrap_or("localhost");

    // Verify certificate exists
    let cert_path = paths.ensure_cert_exists(cert_name)?;
    let key_path = paths.key_path(cert_name)?;

    println!("Watching certificate: {}", cert_name);
    println!("  Cert: {}", cert_path.display());
    println!("  Key:  {}", key_path.display());
    println!("  Poll interval: {}s", interval_secs);
    println!();

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Get initial modification times
    let mut last_cert_mtime = get_mtime(&cert_path);
    let mut last_key_mtime = get_mtime(&key_path);

    // Start the child process
    let mut child = spawn_command(exec)?;
    println!("Started: {}", exec);
    println!("Press Ctrl+C to stop.");
    println!();

    let poll_interval = Duration::from_secs(interval_secs);

    while running.load(Ordering::SeqCst) {
        // Check if child has exited
        match child.try_wait() {
            Ok(Some(status)) => {
                println!();
                println!("Process exited with status: {}", status);
                // Restart the process
                child = spawn_command(exec)?;
                println!("Restarted: {}", exec);
            }
            Ok(None) => {
                // Still running, check for cert changes
            }
            Err(e) => {
                eprintln!("Error checking child process: {}", e);
            }
        }

        // Check for certificate changes
        let cert_mtime = get_mtime(&cert_path);
        let key_mtime = get_mtime(&key_path);

        let cert_changed = cert_mtime != last_cert_mtime;
        let key_changed = key_mtime != last_key_mtime;

        if cert_changed || key_changed {
            println!();
            println!("Certificate changed, restarting process...");

            // Terminate the child process gracefully
            terminate_child(&mut child);

            // Update modification times
            last_cert_mtime = cert_mtime;
            last_key_mtime = key_mtime;

            // Restart
            child = spawn_command(exec)?;
            println!("Restarted: {}", exec);
        }

        std::thread::sleep(poll_interval);
    }

    // Graceful shutdown
    println!();
    println!("Shutting down...");
    terminate_child(&mut child);
    println!("Done.");

    Ok(())
}

/// Get file modification time, returns None if file doesn't exist or can't be read
fn get_mtime(path: &PathBuf) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Spawn a command using the shell
fn spawn_command(exec: &str) -> Result<Child> {
    #[cfg(unix)]
    let child = Command::new("sh")
        .arg("-c")
        .arg(exec)
        .stdin(Stdio::null())
        .env_remove("DEVSSL_PASSWORD") // Don't leak password to child process
        .spawn()
        .map_err(|e| Error::Config(format!("Failed to spawn command: {}", e)))?;

    #[cfg(windows)]
    let child = Command::new("cmd")
        .arg("/C")
        .arg(exec)
        .stdin(Stdio::null())
        .env_remove("DEVSSL_PASSWORD") // Don't leak password to child process
        .spawn()
        .map_err(|e| Error::Config(format!("Failed to spawn command: {}", e)))?;

    Ok(child)
}

/// Terminate a child process gracefully (SIGTERM on Unix, then wait)
fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        // Get the PID and validate it's positive
        let pid = child.id();
        if pid > 0 {
            // Send SIGTERM to process, ignoring errors (process may have already exited)
            unsafe {
                // libc::kill returns 0 on success, -1 on error
                // We don't treat errors as fatal since the process may have already exited
                let _ = libc::kill(pid as i32, libc::SIGTERM);
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, just kill the process
        let _ = child.kill();
    }

    // Wait for the process to exit (with timeout)
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    // Force kill if it doesn't respond to SIGTERM
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
}

/// Set up a Ctrl+C handler
/// Returns error if handler cannot be set (Ctrl+C won't work)
fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) -> Result<()> {
    let handler = std::sync::Mutex::new(Some(handler));
    ctrlc::set_handler(move || {
        // Use ok() instead of unwrap() to avoid panic if mutex is poisoned
        if let Ok(mut guard) = handler.lock() {
            if let Some(h) = guard.take() {
                h();
            }
        }
    })
    .map_err(|e| Error::Config(format!("Failed to set Ctrl+C handler: {}", e)))
}

fn cmd_qr(paths: &Paths, save: Option<&std::path::Path>, port: u16, bind: &str) -> Result<()> {
    use qrcode::QrCode;
    use std::io::Write;
    use std::net::TcpListener;

    // Ensure CA exists
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    // Read the CA certificate
    let ca_pem = std::fs::read_to_string(&paths.ca_cert).map_err(|e| Error::ReadFile {
        path: paths.ca_cert.clone(),
        source: e,
    })?;

    // Determine the display IP for the URL
    // If binding to 0.0.0.0 or ::, use the actual local IP in the URL
    let display_ip = if bind == "0.0.0.0" || bind == "::" {
        get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string())
    } else {
        bind.to_string()
    };
    let url = format!("http://{}:{}/ca.crt", display_ip, port);

    // Generate QR code for the URL
    let code = QrCode::new(url.as_bytes())
        .map_err(|e| Error::Config(format!("Failed to generate QR code: {}", e)))?;

    if let Some(save_path) = save {
        // Save as PNG image
        let image = code.render::<image::Luma<u8>>().build();
        image
            .save(save_path)
            .map_err(|e| Error::Config(format!("Failed to save QR code image: {}", e)))?;
        println!("QR code saved to: {}", save_path.display());
        println!("URL encoded: {}", url);
        return Ok(());
    }

    // Display in terminal using Unicode blocks
    println!();
    println!("Scan this QR code to download the CA certificate:");
    println!();
    print_qr_terminal(&code);
    println!();
    println!("URL: {}", url);
    println!();

    // Print security warning if binding to all interfaces
    if bind == "0.0.0.0" || bind == "::" {
        eprintln!("WARNING: The CA certificate is being served on ALL network interfaces.");
        eprintln!("         Anyone on your local network can download it.");
        eprintln!("         Use --bind 127.0.0.1 to restrict to localhost only.");
        eprintln!();
    }

    // Start temporary HTTP server
    println!("Starting temporary HTTP server on {}:{}...", bind, port);
    println!("Server will auto-shutdown after 5 minutes of inactivity or on Ctrl+C.");
    println!();

    let listener = TcpListener::bind(format!("{}:{}", bind, port))
        .map_err(|e| Error::Config(format!("Failed to bind to {}:{}: {}", bind, port, e)))?;

    // Set up graceful shutdown with Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Set listener to non-blocking so we can check the running flag
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Config(format!("Failed to set non-blocking: {}", e)))?;

    // Rate limiting: track connections per IP
    use std::collections::HashMap;
    let mut connections_per_ip: HashMap<String, (usize, SystemTime)> = HashMap::new();
    const MAX_CONNECTIONS_PER_IP: usize = 10;
    const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

    // Auto-shutdown after 5 minutes of inactivity
    let mut last_request = SystemTime::now();
    const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300);

    // Track consecutive errors to prevent infinite loop on persistent errors
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;

    while running.load(Ordering::SeqCst) {
        // Check for inactivity timeout
        match last_request.elapsed() {
            Ok(elapsed) => {
                if elapsed > INACTIVITY_TIMEOUT {
                    println!(
                        "Auto-shutting down after {} seconds of inactivity.",
                        INACTIVITY_TIMEOUT.as_secs()
                    );
                    break;
                }
            }
            Err(e) => {
                // System clock went backwards - reset the timer to now
                eprintln!("Warning: System clock skew detected: {}", e);
                last_request = SystemTime::now();
            }
        }
        match listener.accept() {
            Ok((mut stream, addr)) => {
                consecutive_errors = 0; // Reset on successful accept
                last_request = SystemTime::now(); // Update last request time

                // Rate limiting check
                let ip = addr.ip().to_string();
                let now = SystemTime::now();

                // Clean up old entries
                connections_per_ip.retain(|_, (_, time)| {
                    match now.duration_since(*time) {
                        Ok(d) => d < RATE_LIMIT_WINDOW,
                        Err(e) => {
                            eprintln!("Warning: Time calculation error in rate limiting: {}", e);
                            false // Remove entries with time errors
                        }
                    }
                });

                // Check rate limit
                let (count, _) = connections_per_ip.entry(ip.clone()).or_insert((0, now));
                *count += 1;

                if *count > MAX_CONNECTIONS_PER_IP {
                    eprintln!("Rate limit exceeded for {}", ip);
                    let _ = stream
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n");
                    continue;
                }

                // Read request and parse the path
                let mut buffer = [0; 1024];
                let n = std::io::Read::read(&mut stream, &mut buffer).unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to read from stream: {}", e);
                    0
                });
                let request = String::from_utf8_lossy(&buffer[..n]);

                // Parse the request line to get the path
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                // Only serve the certificate for /ca.crt or / paths
                let response = if path == "/ca.crt" || path == "/" {
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/x-x509-ca-cert\r\n\
                         Content-Disposition: attachment; filename=\"devssl-ca.crt\"\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n\
                         {}",
                        ca_pem.len(),
                        ca_pem
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: 43\r\n\
                     Connection: close\r\n\
                     \r\n\
                     Not found. Use /ca.crt to download the CA."
                        .to_string()
                };

                if let Err(e) = stream.write_all(response.as_bytes()) {
                    eprintln!("Failed to send response: {}", e);
                } else if path == "/ca.crt" || path == "/" {
                    println!("Certificate served to client!");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection pending, sleep briefly and check running flag
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                consecutive_errors += 1;
                eprintln!("Connection failed: {}", e);

                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    return Err(Error::Config(format!(
                        "QR server stopping after {} consecutive connection errors",
                        MAX_CONSECUTIVE_ERRORS
                    )));
                }
            }
        }
    }

    println!();
    println!("Shutting down QR server...");
    Ok(())
}

/// Get local IP address (first non-loopback IPv4)
fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;

    // Create a UDP socket and "connect" to an external address
    // This doesn't actually send any data, but lets us find the local IP
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Print QR code to terminal using Unicode block characters with ANSI colors
fn print_qr_terminal(code: &qrcode::QrCode) {
    let colors = code.to_colors();
    let width = code.width();

    // ANSI escape codes for explicit black/white (works on all terminal themes)
    const WHITE_BG: &str = "\x1b[47m"; // White background
    const BLACK_FG: &str = "\x1b[30m"; // Black foreground
    const RESET: &str = "\x1b[0m";

    // Add quiet zone (border) - QR spec requires light/white quiet zone
    let quiet_zone = 2;
    let total_width = width + quiet_zone * 2;

    // Print top border (white quiet zone)
    for _ in 0..quiet_zone {
        print!("  {}{}", WHITE_BG, BLACK_FG);
        for _ in 0..total_width {
            print!("  "); // Spaces with white background
        }
        println!("{}", RESET);
    }

    // Print QR code rows (2 at a time using half blocks)
    for row in (0..width).step_by(2) {
        print!("  {}{}", WHITE_BG, BLACK_FG);
        // Left quiet zone (white)
        for _ in 0..quiet_zone {
            print!("  ");
        }

        for col in 0..width {
            let top = colors[row * width + col];
            let bottom = if row + 1 < width {
                colors[(row + 1) * width + col]
            } else {
                qrcode::Color::Light
            };

            // QR: Dark = black data, Light = white background
            // Using block characters with white background, black foreground
            let ch = match (top, bottom) {
                (qrcode::Color::Dark, qrcode::Color::Dark) => "\u{2588}\u{2588}", // Full black
                (qrcode::Color::Dark, qrcode::Color::Light) => "\u{2580}\u{2580}", // Upper half black
                (qrcode::Color::Light, qrcode::Color::Dark) => "\u{2584}\u{2584}", // Lower half black
                (qrcode::Color::Light, qrcode::Color::Light) => "  ",              // White (spaces)
            };
            print!("{}", ch);
        }

        // Right quiet zone (white)
        for _ in 0..quiet_zone {
            print!("  ");
        }
        println!("{}", RESET);
    }

    // Print bottom border (white quiet zone)
    for _ in 0..quiet_zone {
        print!("  {}{}", WHITE_BG, BLACK_FG);
        for _ in 0..total_width {
            print!("  ");
        }
        println!("{}", RESET);
    }
}

fn cmd_doctor(paths: &Paths) -> Result<()> {
    println!("Checking devssl installation...");
    println!();

    let mut has_issues = false;

    // 1. Check CA exists and is valid
    if paths.ca_exists() {
        println!("{} CA exists", check_mark());

        if let Ok(info) = devssl::parse_cert_file(&paths.ca_cert) {
            let days = info.days_remaining();
            if days < 0 {
                println!("{} CA expired ({} days ago)", cross_mark(), -days);
                has_issues = true;
            } else {
                println!(
                    "{} CA valid (expires {})",
                    check_mark(),
                    info.expiry_string()
                );
            }
        } else {
            println!("{} CA certificate unreadable", cross_mark());
            has_issues = true;
        }
    } else {
        println!("{} CA not initialized", cross_mark());
        println!("  Run: devssl init");
        return Ok(());
    }

    // 2. Check CA is trusted in system store
    let trust = get_trust_store();
    match trust.is_trusted(&paths.ca_cert) {
        Ok(true) => println!("{} CA trusted in system store", check_mark()),
        Ok(false) => {
            println!("{} CA NOT trusted in system store", cross_mark());
            println!("  Run: devssl init --force");
            has_issues = true;
        }
        Err(_) => {
            println!("? CA trust status unknown");
        }
    }

    // 3. Firefox NSS status (Linux only, if certutil available)
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let certutil_available = Command::new("which")
            .arg("certutil")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if certutil_available {
            let (installed_count, db_count) = check_browser_nss(&paths.ca_cert);
            if db_count == 0 {
                println!("- Browser NSS: no databases found");
            } else if installed_count == db_count {
                println!(
                    "{} Browser NSS: installed in {}/{} database(s)",
                    check_mark(),
                    installed_count,
                    db_count
                );
            } else {
                println!(
                    "{} Browser NSS: installed in {}/{} database(s)",
                    cross_mark(),
                    installed_count,
                    db_count
                );
                has_issues = true;
            }
        } else {
            println!("- Browser NSS: certutil not installed");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("- Browser NSS: skipped (not on Linux)");
    }

    // 4. Check NODE_EXTRA_CA_CERTS
    let node_ca_env = std::env::var("NODE_EXTRA_CA_CERTS").ok();
    let expected_ca_path = paths.ca_cert.to_string_lossy().to_string();

    match node_ca_env {
        Some(ref path) if path == &expected_ca_path => {
            println!("{} NODE_EXTRA_CA_CERTS set correctly", check_mark());
        }
        Some(ref path) => {
            println!(
                "{} NODE_EXTRA_CA_CERTS points to different CA",
                cross_mark()
            );
            println!("  Current: {}", path);
            println!(
                "  Run: export NODE_EXTRA_CA_CERTS=\"{}\"",
                paths.ca_cert.display()
            );
            has_issues = true;
        }
        None => {
            println!("{} NODE_EXTRA_CA_CERTS not set", cross_mark());
            println!(
                "  Run: export NODE_EXTRA_CA_CERTS=\"{}\"",
                paths.ca_cert.display()
            );
            has_issues = true;
        }
    }

    println!();

    // 5. List certificates with status
    println!("Certificates:");
    let certs = match list_certificates(paths) {
        Ok(c) => c,
        Err(_) => {
            println!("  (could not read certificate directory)");
            return Ok(());
        }
    };

    if certs.is_empty() {
        println!("  (none)");
    } else {
        for (name, path) in certs {
            if let Ok(info) = devssl::parse_cert_file(&path) {
                let days = info.days_remaining();
                if days < 0 {
                    println!("  {:16} {} expired", name, cross_mark());
                    has_issues = true;
                } else {
                    println!(
                        "  {:16} {} valid ({} days remaining)",
                        name,
                        check_mark(),
                        days
                    );
                }
            } else {
                println!("  {:16} ? unreadable", name);
            }
        }
    }

    // 6. Daemon status
    println!();
    println!("Daemon:");
    let daemon_status = devssl::daemon::status(paths);
    if daemon_status.running {
        if let Some(pid) = daemon_status.pid {
            println!("  {} Running (PID: {})", check_mark(), pid);
        } else {
            println!("  {} Running (PID unknown)", check_mark());
        }
    } else {
        println!("  - Not running");
        println!("    To enable auto-renewal: devssl daemon start");
    }

    if has_issues {
        println!();
        println!("Some issues were found. See suggestions above.");
    }

    Ok(())
}

fn check_mark() -> &'static str {
    "\u{2713}" // Unicode checkmark
}

fn cross_mark() -> &'static str {
    "\u{2717}" // Unicode cross mark
}

fn cmd_export_ca(
    paths: &Paths,
    include_key: bool,
    output: Option<&std::path::Path>,
    format: ExportFormat,
) -> Result<()> {
    use std::io::Write;

    // Ensure CA exists
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    // Read the CA certificate
    let ca_cert_pem = std::fs::read_to_string(&paths.ca_cert).map_err(|e| Error::ReadFile {
        path: paths.ca_cert.clone(),
        source: e,
    })?;

    // Parse certificate to get fingerprint for verification
    let cert_info = devssl::parse_cert_file(&paths.ca_cert)?;
    let fingerprint = compute_ca_fingerprint(&paths.ca_cert)?;

    // Build output content
    let mut content = Vec::new();

    match format {
        ExportFormat::Pem => {
            // Add header comment with fingerprint for verification
            let header = format!(
                "# devssl CA Certificate\n# Fingerprint (SHA-256): {}\n# Expires: {}\n#\n",
                fingerprint,
                cert_info.expiry_string()
            );
            content.extend_from_slice(header.as_bytes());
            content.extend_from_slice(ca_cert_pem.as_bytes());

            if include_key {
                eprintln!();
                eprintln!("WARNING: The CA private key can sign certificates for ANY domain.");
                eprintln!("         Share securely and only with trusted team members!");
                eprintln!();

                let ca_key_pem =
                    std::fs::read_to_string(&paths.ca_key).map_err(|e| Error::ReadFile {
                        path: paths.ca_key.clone(),
                        source: e,
                    })?;
                content.extend_from_slice(b"\n");
                content.extend_from_slice(ca_key_pem.as_bytes());
            }
        }
        ExportFormat::Der => {
            // Parse PEM to get DER bytes
            let pem = pem::parse(&ca_cert_pem)
                .map_err(|e| Error::CertParse(format!("Failed to parse CA PEM: {}", e)))?;
            content = pem.contents().to_vec();

            if include_key {
                return Err(Error::Config(
                    "DER format does not support including the private key. Use PEM format instead."
                        .to_string(),
                ));
            }
        }
    }

    // Output
    if let Some(output_path) = output {
        if include_key {
            devssl::write_secret_file(output_path, &content)?;
        } else {
            std::fs::write(output_path, &content).map_err(|e| Error::WriteFile {
                path: output_path.to_path_buf(),
                source: e,
            })?;
        }
        println!("CA certificate exported to: {}", output_path.display());
    } else {
        std::io::stdout()
            .write_all(&content)
            .map_err(|e| Error::Config(format!("Failed to write to stdout: {}", e)))?;
    }

    // Print fingerprint info for verification
    if output.is_some() || include_key {
        println!();
        println!("CA Fingerprint (SHA-256): {}", fingerprint);
        println!("Team members should verify this fingerprint matches after import.");
    }

    Ok(())
}

fn cmd_import_ca(paths: &Paths, file: &std::path::Path, trust: bool, force: bool) -> Result<()> {
    // Check if CA already exists
    if paths.ca_exists() {
        eprintln!(
            "WARNING: A CA already exists at {}",
            paths.ca_cert.display()
        );
        eprintln!("         Importing will replace it. Existing certificates may stop working.");
        eprintln!();

        if !confirm_prompt("Continue?") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Read the input file
    let file_content = std::fs::read(file).map_err(|e| Error::ReadFile {
        path: file.to_path_buf(),
        source: e,
    })?;

    // Detect format (PEM or DER)
    // PEM files may have comments/headers before the -----BEGIN marker
    let content_str = String::from_utf8_lossy(&file_content);
    let (cert_pem, key_pem) = if content_str.contains("-----BEGIN") {
        // PEM format
        parse_pem_bundle(&content_str)?
    } else {
        // Assume DER format - convert to PEM
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", file_content));
        (cert_pem, None)
    };

    // Validate the certificate
    let cert_info = devssl::parse_cert_pem(&cert_pem)?;

    // Check if it's a CA certificate using BasicConstraints extension
    let cn = cert_info.common_name.as_deref().unwrap_or("Unknown");
    if !cert_info.is_ca {
        eprintln!(
            "ERROR: This certificate is not a CA certificate (BasicConstraints CA:FALSE or missing)"
        );
        eprintln!("       Common Name: {}", cn);
        if !force {
            eprintln!();
            eprintln!("Use --force to import anyway (not recommended).");
            return Err(Error::CertParse(
                "Certificate is not a CA (missing BasicConstraints CA:TRUE)".to_string(),
            ));
        }
        eprintln!();
        eprintln!("WARNING: Proceeding with --force. This certificate may not work as a CA.");
    }

    // Check expiry
    if cert_info.is_expired() {
        return Err(Error::CertParse(
            "The CA certificate has expired".to_string(),
        ));
    }

    // Compute fingerprint for verification
    let fingerprint = compute_fingerprint_from_pem(&cert_pem)?;

    // Display security warning
    eprintln!();
    eprintln!("WARNING: You are trusting a CA that can sign certificates for any domain.");
    eprintln!("         Only import CA certificates from trusted sources!");
    eprintln!();
    eprintln!("CA Details:");
    eprintln!("  Common Name: {}", cn);
    eprintln!("  Expires: {}", cert_info.expiry_string());
    eprintln!("  Fingerprint (SHA-256): {}", fingerprint);
    eprintln!();

    // Confirm import
    if !confirm_prompt("Verify the fingerprint and confirm import?") {
        println!("Aborted.");
        return Ok(());
    }

    // Ensure directory exists
    paths.ensure_dir()?;

    // Save certificate
    std::fs::write(&paths.ca_cert, &cert_pem).map_err(|e| Error::WriteFile {
        path: paths.ca_cert.clone(),
        source: e,
    })?;
    println!("CA certificate saved to: {}", paths.ca_cert.display());

    // Save key if provided
    let has_key = if let Some(key) = key_pem {
        devssl::write_secret_file(&paths.ca_key, key.as_bytes())?;
        println!("CA private key saved to: {}", paths.ca_key.display());
        true
    } else {
        // Remove any existing key file to prevent mismatched key usage
        if paths.ca_key.exists() {
            std::fs::remove_file(&paths.ca_key).ok();
        }
        println!("Note: No private key included - this CA is read-only.");
        println!("      You can trust certificates but cannot generate new ones.");
        false
    };

    // Add to trust store if requested
    if trust {
        println!();
        println!("Adding CA to system trust store...");
        let trust_store = get_trust_store();
        trust_store.add_ca(&paths.ca_cert)?;
        println!("Added to {}", trust_store.name());
    }

    println!();
    println!("CA import complete!");
    if has_key {
        println!("You can now generate new certificates with 'devssl generate'");
    } else {
        println!("Run 'devssl import-ca --trust <file>' to add to trust store.");
    }

    Ok(())
}

/// Compute SHA-256 fingerprint of a certificate file
fn compute_ca_fingerprint(cert_path: &std::path::Path) -> Result<String> {
    let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| Error::ReadFile {
        path: cert_path.to_path_buf(),
        source: e,
    })?;
    compute_fingerprint_from_pem(&cert_pem)
}

/// Compute SHA-256 fingerprint from PEM string
fn compute_fingerprint_from_pem(pem_str: &str) -> Result<String> {
    use sha2::{Digest, Sha256};

    let pem =
        pem::parse(pem_str).map_err(|e| Error::CertParse(format!("Failed to parse PEM: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(pem.contents());
    let hash = hasher.finalize();

    // Format as colon-separated hex
    let fingerprint = hash
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(fingerprint)
}

/// Parse a PEM bundle to extract certificate and optional private key
fn parse_pem_bundle(content: &str) -> Result<(String, Option<String>)> {
    let mut cert_pem = None;
    let mut key_pem = None;

    for pem in pem::parse_many(content)
        .map_err(|e| Error::CertParse(format!("Failed to parse PEM bundle: {}", e)))?
    {
        match pem.tag() {
            "CERTIFICATE" => {
                if cert_pem.is_none() {
                    cert_pem = Some(pem::encode(&pem));
                }
            }
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                if key_pem.is_none() {
                    key_pem = Some(pem::encode(&pem));
                }
            }
            _ => {} // Ignore other types
        }
    }

    let cert =
        cert_pem.ok_or_else(|| Error::CertParse("No certificate found in file".to_string()))?;

    Ok((cert, key_pem))
}

/// Check browser NSS databases (Chrome, Firefox) for installed CA certificate
#[cfg(target_os = "linux")]
fn check_browser_nss(_cert_path: &std::path::Path) -> (usize, usize) {
    use std::path::PathBuf;
    use std::process::Command;

    const NSS_CERT_NAME: &str = "devssl Local CA";

    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return (0, 0),
    };

    let mut databases: Vec<PathBuf> = Vec::new();

    // Chrome/Chromium NSS database
    let chrome_nss = home.join(".pki").join("nssdb");
    if chrome_nss.exists() && chrome_nss.join("cert9.db").exists() {
        databases.push(chrome_nss);
    }

    // Firefox profile directories
    let firefox_dirs = [
        home.join(".mozilla").join("firefox"),
        home.join("snap")
            .join("firefox")
            .join("common")
            .join(".mozilla")
            .join("firefox"),
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
        if let Ok(entries) = std::fs::read_dir(firefox_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.contains(".default")
                            && (path.join("cert9.db").exists() || path.join("cert8.db").exists())
                        {
                            databases.push(path);
                        }
                    }
                }
            }
        }
    }

    let db_count = databases.len();
    let mut installed_count = 0;

    for db_path in databases {
        let db_path_str = match db_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let nss_db = format!("sql:{}", db_path_str);
        let output = Command::new("certutil")
            .args(["-d", &nss_db, "-L", "-n", NSS_CERT_NAME])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                installed_count += 1;
            }
        }
    }

    (installed_count, db_count)
}

fn cmd_daemon(paths: &Paths, action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Start {
            on_renew,
            ca_password,
        } => {
            // Get password for encrypted CA keys
            let password = if paths.ca_key_is_encrypted() {
                Some(get_password(
                    ca_password,
                    "DEVSSL_PASSWORD",
                    "Enter CA key password: ",
                )?)
            } else {
                None
            };
            println!("Starting daemon...");
            let pid = devssl::daemon::start(paths, on_renew.as_deref(), password.as_deref())?;
            println!("Daemon started (PID: {})", pid);
            println!("Log file: {}", paths.log_path().display());
            Ok(())
        }
        DaemonAction::Stop => {
            devssl::daemon::stop(paths)?;
            println!("Daemon stopped");
            Ok(())
        }
        DaemonAction::Status => {
            let status = devssl::daemon::status(paths);
            if status.running {
                if let Some(pid) = status.pid {
                    println!("Daemon: running (PID: {})", pid);
                } else {
                    println!("Daemon: running (PID unknown)");
                }
            } else {
                println!("Daemon: not running");
            }
            println!("Log file: {}", status.log_path.display());

            // Show configuration
            let config = Config::load(&paths.config)?;
            println!();
            println!("Configuration:");
            println!(
                "  Check interval: {} hour(s)",
                config.daemon.check_interval_hours
            );
            println!("  Renew within: {} days", config.daemon.renew_within_days);
            Ok(())
        }
        DaemonAction::Run {
            on_renew,
            ca_password,
        } => {
            // Get password for encrypted CA keys
            // For run mode, also check DEVSSL_PASSWORD env var (may be set by start())
            let password = if paths.ca_key_is_encrypted() {
                let pwd = ca_password
                    .or_else(|| std::env::var("DEVSSL_PASSWORD").ok().filter(|s| !s.is_empty()))
                    .ok_or_else(|| Error::Config(
                        "CA key is encrypted but no password provided. Set DEVSSL_PASSWORD env var or use --ca-password".to_string()
                    ))?;
                Some(pwd)
            } else {
                None
            };
            let config = Config::load(&paths.config)?;
            devssl::daemon::run(paths, &config, on_renew.as_deref(), password.as_deref())
        }
        DaemonAction::Logs { lines, follow } => {
            let log_path = paths.log_path();

            if !log_path.exists() {
                println!("No log file found at {}", log_path.display());
                println!("The daemon may not have been started yet.");
                return Ok(());
            }

            if follow {
                // Follow mode: tail -f style
                use std::io::{BufRead, BufReader, Seek, SeekFrom};
                use std::thread;
                use std::time::Duration;

                let file = std::fs::File::open(&log_path).map_err(|e| Error::ReadFile {
                    path: log_path.clone(),
                    source: e,
                })?;
                let mut reader = BufReader::new(file);

                // Seek to end to start following
                reader.seek(SeekFrom::End(0)).map_err(|e| Error::ReadFile {
                    path: log_path.clone(),
                    source: e,
                })?;

                println!("Following {}... (Ctrl+C to stop)", log_path.display());
                println!();

                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            // No new data, sleep briefly
                            thread::sleep(Duration::from_millis(100));
                        }
                        Ok(_) => {
                            print!("{}", line);
                        }
                        Err(e) => {
                            eprintln!("Error reading log: {}", e);
                            break;
                        }
                    }
                }
            } else {
                // Show last N lines
                let content = std::fs::read_to_string(&log_path).map_err(|e| Error::ReadFile {
                    path: log_path.clone(),
                    source: e,
                })?;

                let all_lines: Vec<&str> = content.lines().collect();
                let start = all_lines.len().saturating_sub(lines);
                for line in &all_lines[start..] {
                    println!("{}", line);
                }

                if all_lines.is_empty() {
                    println!("Log file is empty.");
                }
            }

            Ok(())
        }
    }
}

fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "devssl", &mut std::io::stdout());
    Ok(())
}

/// Get password from command line argument, environment variable, or prompt
fn get_password(arg: Option<String>, env_var: &str, prompt: &str) -> Result<String> {
    // First check command line argument
    if let Some(pwd) = arg {
        if pwd.is_empty() {
            return Err(Error::Config("Password cannot be empty".to_string()));
        }
        eprintln!(
            "Warning: Password provided via command line is visible in process list.\n\
             Consider using {} env var or interactive prompt instead.",
            env_var
        );
        return Ok(pwd);
    }

    // Then check environment variable
    if let Ok(pwd) = std::env::var(env_var) {
        if pwd.is_empty() {
            return Err(Error::Config(format!(
                "{} is set but empty. Password cannot be empty.",
                env_var
            )));
        }
        return Ok(pwd);
    }

    // Finally prompt the user
    let pwd = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Config(format!("Failed to read password: {}", e)))?;

    if pwd.is_empty() {
        return Err(Error::Config("Password cannot be empty".to_string()));
    }

    Ok(pwd)
}

/// Load CA with optional password support
fn load_ca_with_password(paths: &Paths, ca_password: Option<String>) -> Result<Ca> {
    if paths.ca_key_is_encrypted() {
        let password = get_password(ca_password, "DEVSSL_PASSWORD", "Enter CA key password: ")?;
        Ca::load_with_password(paths, Some(&password))
    } else {
        Ca::load(paths)
    }
}

/// Get password for encryption with confirmation
fn get_password_for_encryption(arg_password: Option<&str>) -> Result<String> {
    if let Some(pwd) = arg_password {
        eprintln!(
            "Warning: Password provided via command line is visible in process list.\n\
             Consider using DEVSSL_PASSWORD env var or interactive prompt instead."
        );
        return Ok(pwd.to_string());
    }

    if let Ok(pwd) = std::env::var("DEVSSL_PASSWORD") {
        return Ok(pwd);
    }

    // Interactive prompt with confirmation
    prompt_password_with_confirm(
        "Enter password for CA key encryption: ",
        "Confirm password: ",
    )
}

/// Encrypt an existing unencrypted CA key
fn cmd_encrypt_key(paths: &Paths, password: Option<String>) -> Result<()> {
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    if paths.ca_key_is_encrypted() {
        return Err(Error::Config(
            "CA key is already encrypted. Use change-password to change it.".to_string(),
        ));
    }

    if !paths.ca_key.exists() {
        return Err(Error::Config("No unencrypted CA key found".to_string()));
    }

    let password = get_password_for_encryption(password.as_deref())?;

    println!("Encrypting CA key...");
    encrypt_existing_key(paths, &password)?;

    println!("CA key encrypted successfully.");
    println!("Encrypted key: {}", paths.ca_key_enc.display());
    println!();
    println!("Note: The unencrypted key has been securely removed.");
    println!("      You will need the password to sign new certificates.");

    Ok(())
}

/// Decrypt an encrypted CA key (removes password protection)
fn cmd_decrypt_key(paths: &Paths, password: Option<String>) -> Result<()> {
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    if !paths.ca_key_is_encrypted() {
        return Err(Error::KeyNotEncrypted);
    }

    let password = get_password(password, "DEVSSL_PASSWORD", "Enter CA key password: ")?;

    eprintln!();
    eprintln!("WARNING: Decrypting the CA key removes password protection.");
    eprintln!("         The key will be stored unencrypted on disk.");
    eprintln!();

    if !confirm_prompt("Continue?") {
        println!("Aborted.");
        return Ok(());
    }

    println!("Decrypting CA key...");
    decrypt_existing_key(paths, &password)?;

    println!("CA key decrypted successfully.");
    println!("Unencrypted key: {}", paths.ca_key.display());

    Ok(())
}

/// Change the password on an encrypted CA key
fn cmd_change_password(
    paths: &Paths,
    old_password: Option<String>,
    new_password: Option<String>,
) -> Result<()> {
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    if !paths.ca_key_is_encrypted() {
        return Err(Error::KeyNotEncrypted);
    }

    let old_pwd = get_password(
        old_password,
        "DEVSSL_PASSWORD",
        "Enter current CA key password: ",
    )?;

    let new_pwd = if let Some(pwd) = new_password {
        eprintln!(
            "Warning: Password provided via command line is visible in process list.\n\
             Consider using DEVSSL_NEW_PASSWORD env var or interactive prompt instead."
        );
        pwd
    } else if let Ok(pwd) = std::env::var("DEVSSL_NEW_PASSWORD") {
        pwd
    } else {
        // Interactive prompt with confirmation
        prompt_new_password()?
    };

    println!("Changing CA key password...");
    change_key_password(paths, &old_pwd, &new_pwd)?;

    println!("CA key password changed successfully.");

    Ok(())
}

fn cmd_backup(paths: &Paths, output: Option<std::path::PathBuf>) -> Result<()> {
    if !paths.ca_exists() {
        return Err(Error::CaNotInitialized);
    }

    // Check if daemon is running and warn user
    let daemon_status = daemon::status(paths);
    if daemon_status.running {
        println!(
            "Warning: Daemon is running (PID: {}). Stopping it during backup...",
            daemon_status.pid.unwrap_or(0)
        );
        daemon::stop(paths)?;
        println!("Daemon stopped. Proceeding with backup.");
    }

    // Acquire daemon lock to prevent daemon from starting during backup
    let _lock = daemon::DaemonLock::try_acquire(paths).map_err(|_| {
        Error::Config(
            "Failed to acquire lock. Another daemon may be starting. Please try again.".to_string(),
        )
    })?;

    let backup_path = output.unwrap_or_else(|| std::path::PathBuf::from("devssl-backup"));

    if backup_path.exists() {
        return Err(Error::Config(format!(
            "Backup destination '{}' already exists. Remove it first or choose a different path.",
            backup_path.display()
        )));
    }

    println!("Creating backup...");

    // Create backup directory
    std::fs::create_dir_all(&backup_path).map_err(|e| Error::CreateDir {
        path: backup_path.clone(),
        source: e,
    })?;

    // Copy all files from devssl directory
    let entries = std::fs::read_dir(&paths.base).map_err(|e| Error::ReadDir {
        path: paths.base.clone(),
        source: e,
    })?;

    let mut count = 0;
    for entry in entries.flatten() {
        let src = entry.path();
        if src.is_file() {
            let Some(filename) = src.file_name() else {
                continue;
            };
            let dest = backup_path.join(filename);
            std::fs::copy(&src, &dest).map_err(|e| Error::WriteFile {
                path: dest.clone(),
                source: e,
            })?;
            count += 1;
        }
    }

    println!("Backed up {} files to '{}'", count, backup_path.display());
    println!();
    println!("To restore: devssl restore '{}'", backup_path.display());

    Ok(())
}

fn cmd_restore(paths: &Paths, backup_path: &std::path::Path, force: bool) -> Result<()> {
    if !backup_path.exists() {
        return Err(Error::Config(format!(
            "Backup '{}' not found.",
            backup_path.display()
        )));
    }

    if !backup_path.is_dir() {
        return Err(Error::Config(format!(
            "'{}' is not a directory. Expected a devssl backup directory.",
            backup_path.display()
        )));
    }

    // Check for CA files in backup
    let ca_cert = backup_path.join("ca.crt");
    if !ca_cert.exists() {
        return Err(Error::Config(format!(
            "Invalid backup: ca.crt not found in '{}'",
            backup_path.display()
        )));
    }

    // Check if destination exists
    if paths.ca_exists() && !force {
        return Err(Error::Config(
            "CA already exists. Use --force to overwrite.".to_string(),
        ));
    }

    // Check if daemon is running and warn user
    let daemon_status = daemon::status(paths);
    if daemon_status.running {
        println!(
            "Warning: Daemon is running (PID: {}). Stopping it during restore...",
            daemon_status.pid.unwrap_or(0)
        );
        daemon::stop(paths)?;
        println!("Daemon stopped. Proceeding with restore.");
    }

    // Acquire daemon lock to prevent daemon from starting during restore
    let _lock = daemon::DaemonLock::try_acquire(paths).map_err(|_| {
        Error::Config(
            "Failed to acquire lock. Another daemon may be starting. Please try again.".to_string(),
        )
    })?;

    println!("Restoring from backup...");

    // Create destination directory
    std::fs::create_dir_all(&paths.base).map_err(|e| Error::CreateDir {
        path: paths.base.clone(),
        source: e,
    })?;

    // Copy all files from backup
    let entries = std::fs::read_dir(backup_path).map_err(|e| Error::ReadDir {
        path: backup_path.to_path_buf(),
        source: e,
    })?;

    let mut count = 0;
    for entry in entries.flatten() {
        let src = entry.path();
        if src.is_file() {
            let Some(filename) = src.file_name() else {
                continue;
            };
            let dest = paths.base.join(filename);
            std::fs::copy(&src, &dest).map_err(|e| Error::WriteFile {
                path: dest.clone(),
                source: e,
            })?;
            count += 1;
        }
    }

    println!("Restored {} files from backup.", count);
    println!();
    println!("Note: Run 'devssl trust install' to add CA to system trust store.");

    Ok(())
}

fn cmd_trust(paths: &Paths, action: TrustAction) -> Result<()> {
    match action {
        TrustAction::Install => {
            if !paths.ca_exists() {
                return Err(Error::CaNotInitialized);
            }

            let trust = get_trust_store();

            // Check if already trusted
            match trust.is_trusted(&paths.ca_cert) {
                Ok(true) => {
                    println!("CA is already trusted in {}.", trust.name());
                    return Ok(());
                }
                Ok(false) => {}
                Err(_) => {}
            }

            println!("Adding CA to system trust store...");
            trust.add_ca(&paths.ca_cert)?;
            println!("CA added to {}.", trust.name());
            println!();
            println!("Note: Restart your browser for changes to take effect.");

            Ok(())
        }
        TrustAction::Remove => {
            if !paths.ca_exists() {
                return Err(Error::CaNotInitialized);
            }

            let trust = get_trust_store();

            // Check if actually trusted
            match trust.is_trusted(&paths.ca_cert) {
                Ok(false) => {
                    println!("CA is not in system trust store.");
                    return Ok(());
                }
                Ok(true) => {}
                Err(_) => {}
            }

            println!("Removing CA from system trust store...");
            trust.remove_ca(&paths.ca_cert)?;
            println!("CA removed from {}.", trust.name());

            Ok(())
        }
        TrustAction::Status => {
            if !paths.ca_exists() {
                println!("CA not initialized. Run 'devssl init' first.");
                return Ok(());
            }

            let trust = get_trust_store();
            println!("Trust store: {}", trust.name());

            match trust.is_trusted(&paths.ca_cert) {
                Ok(true) => println!("Status: CA is trusted"),
                Ok(false) => println!("Status: CA is NOT trusted"),
                Err(e) => println!("Status: Unable to check ({})", e),
            }

            Ok(())
        }
    }
}

# Rust Actix-web with devssl

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Run your Actix app
cargo run  # Listening on http://127.0.0.1:8080

# Terminal 2: Start HTTPS proxy
devssl proxy 8080
```

Access at `https://localhost:8080`.

## Option 2: Native TLS

### Cargo.toml

```toml
[dependencies]
actix-web = { version = "4", features = ["rustls-0_23"] }
rustls = "0.23"
rustls-pemfile = "2"
```

### main.rs

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;

fn load_rustls_config() -> ServerConfig {
    let cert_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("devssl");

    let cert_file = File::open(cert_dir.join("localhost.crt"))
        .expect("Cannot open certificate file");
    let key_file = File::open(cert_dir.join("localhost.key"))
        .expect("Cannot open key file");

    let cert_chain = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();
    let key = private_key(&mut BufReader::new(key_file))
        .expect("Cannot read private key")
        .expect("No private key found");

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("Failed to build TLS config")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = load_rustls_config();

    HttpServer::new(|| {
        App::new().route("/", web::get().to(|| async {
            HttpResponse::Ok().body("Hello from HTTPS!")
        }))
    })
    .bind_rustls_0_23("127.0.0.1:8080", config)?
    .run()
    .await
}
```

### Run

```bash
devssl init
cargo run
```

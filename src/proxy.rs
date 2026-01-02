// Copyright 2025 Jayashankar
// SPDX-License-Identifier: Apache-2.0

//! HTTPS proxy: terminates TLS and forwards to a local HTTP backend.
//! Supports WebSocket upgrade requests and optional HTTP-to-HTTPS redirect.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_LENGTH;
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // shutdown() comes from AsyncWriteExt
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

/// Graceful shutdown timeout for draining in-flight connections.
const GRACEFUL_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

use crate::{Error, Result};

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>;

/// Default maximum body size for proxied requests (10 MB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

const MAX_CONNECTIONS: usize = 1024;
const WEBSOCKET_BUFFER_SIZE: usize = 16 * 1024;
const MAX_WEBSOCKET_HEADER_SIZE: usize = 64 * 1024;

fn error_response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Internal Server Error"))))
}

/// Load TLS config from cert/key files (validates expiry).
pub async fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    // Blocking I/O
    let cert_path_owned = cert_path.to_path_buf();
    let key_path_owned = key_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let cert_pem = std::fs::read_to_string(&cert_path_owned).map_err(|e| Error::ReadFile {
            path: cert_path_owned.clone(),
            source: e,
        })?;

        if let Ok(cert_info) = crate::x509::parse_cert_pem(&cert_pem) {
            if cert_info.is_expired() {
                return Err(Error::Config(format!(
                    "Certificate {} has expired. Run 'devssl renew' to renew it.",
                    cert_path_owned.display()
                )));
            }
        }

        let cert_file = std::fs::File::open(&cert_path_owned).map_err(|e| Error::ReadFile {
            path: cert_path_owned.clone(),
            source: e,
        })?;

        let mut cert_chain = Vec::new();
        for (i, result) in certs(&mut BufReader::new(cert_file)).enumerate() {
            match result {
                Ok(cert) => cert_chain.push(cert),
                Err(e) => {
                    return Err(Error::Config(format!(
                        "Failed to parse certificate {} in chain: {}",
                        i + 1,
                        e
                    )));
                }
            }
        }

        if cert_chain.is_empty() {
            return Err(Error::Config("No certificates found in cert file".into()));
        }

        let key_file = std::fs::File::open(&key_path_owned).map_err(|e| Error::ReadFile {
            path: key_path_owned.clone(),
            source: e,
        })?;
        let key = private_key(&mut BufReader::new(key_file))
            .map_err(|e| Error::Config(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| Error::Config("No private key found in key file".into()))?;

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| Error::Config(format!("TLS error: {}", e)))
    })
    .await
    .map_err(|e| Error::Config(format!("Task join error: {}", e)))?
}

/// HTTP-to-HTTPS redirect server config.
#[derive(Clone)]
pub struct RedirectConfig {
    pub http_port: u16,
    pub https_port: u16,
    pub host: String,
    pub bind: String,
}

/// Run HTTPS proxy (no redirect).
pub async fn run_proxy(
    listen_addr: SocketAddr,
    backend_addr: String,
    tls_config: ServerConfig,
) -> Result<()> {
    run_proxy_with_redirect(
        listen_addr,
        backend_addr,
        tls_config,
        None,
        DEFAULT_MAX_BODY_SIZE,
    )
    .await
}

/// Run HTTPS proxy with optional HTTP redirect.
pub async fn run_proxy_with_redirect(
    listen_addr: SocketAddr,
    backend_addr: String,
    tls_config: ServerConfig,
    redirect_config: Option<RedirectConfig>,
    max_body_size: usize,
) -> Result<()> {
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| Error::Config(format!("Failed to bind to {}: {}", listen_addr, e)))?;

    let client: HttpClient = Client::builder(TokioExecutor::new()).build_http();
    let client = Arc::new(client);

    // Connection limiter
    let connection_semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    println!("HTTPS proxy listening on https://{}", listen_addr);
    println!("Forwarding to http://{}", backend_addr);

    if let Some(ref redirect) = redirect_config {
        let redirect_addr: SocketAddr = format!("{}:{}", redirect.bind, redirect.http_port)
            .parse()
            .map_err(|e| Error::Config(format!("Invalid redirect address: {}", e)))?;

        let redirect_listener = TcpListener::bind(redirect_addr).await.map_err(|e| {
            Error::Config(format!(
                "Failed to bind HTTP redirect to {}: {}",
                redirect_addr, e
            ))
        })?;

        println!(
            "HTTP redirect listening on http://{} -> https://{}:{}",
            redirect_addr, redirect.host, redirect.https_port
        );

        let redirect_config = redirect.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            run_redirect_server(redirect_listener, redirect_config, shutdown_rx).await;
        });
    }

    println!("Press Ctrl+C to stop");

    // Track all spawned connection tasks for graceful shutdown
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            // Handle Ctrl+C signal
            _ = signal::ctrl_c() => {
                println!("\nShutting down gracefully...");

                // Notify redirect server to stop accepting
                let _ = shutdown_tx.send(());

                // Wait for in-flight connections with timeout
                let active_count = connection_tasks.len();
                if active_count > 0 {
                    println!("Waiting for {} active connection(s) to complete (timeout: {}s)...",
                             active_count, GRACEFUL_SHUTDOWN_TIMEOUT.as_secs());

                    let drain_result = tokio::time::timeout(
                        GRACEFUL_SHUTDOWN_TIMEOUT,
                        drain_connections(&mut connection_tasks)
                    ).await;

                    match drain_result {
                        Ok(_) => println!("All connections completed."),
                        Err(_) => {
                            let remaining = connection_tasks.len();
                            println!("Timeout reached, aborting {} remaining connection(s).", remaining);
                            connection_tasks.abort_all();
                        }
                    }
                }

                println!("Proxy stopped.");
                return Ok(());
            }

            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, peer_addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                        continue;
                    }
                };

                // Acquire permit from semaphore (limits concurrent connections)
                let permit = match connection_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Too many connections, drop this one
                        eprintln!("Connection limit reached, rejecting connection from {}", peer_addr);
                        drop(stream);
                        continue;
                    }
                };

                let acceptor = tls_acceptor.clone();
                let backend = backend_addr.clone();
                let client = Arc::clone(&client);
                let body_limit = max_body_size;

                // Spawn connection handler and track it in JoinSet
                connection_tasks.spawn(async move {
                    // Hold the permit for the duration of the connection
                    let _permit = permit;

                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // Check if this might be a WebSocket upgrade
                            // We need to handle the connection with upgrades enabled
                            let io = TokioIo::new(tls_stream);
                            let peer = peer_addr;
                            let svc = service_fn(move |req| {
                                handle_request(req, backend.clone(), Arc::clone(&client), peer, body_limit)
                            });

                            let conn = http1::Builder::new()
                                .serve_connection(io, svc)
                                .with_upgrades();

                            if let Err(e) = conn.await {
                                if !e.to_string().contains("connection closed") {
                                    eprintln!("Connection error from {}: {}", peer_addr, e);
                                }
                            }
                        }
                        Err(e) => eprintln!("TLS handshake failed from {}: {}", peer_addr, e),
                    }
                });

                // Clean up completed tasks to prevent unbounded growth
                while connection_tasks.try_join_next().is_some() {}
            }
        }
    }
}

/// Drain all connections from the JoinSet, waiting for each to complete.
async fn drain_connections(tasks: &mut JoinSet<()>) {
    while tasks.join_next().await.is_some() {}
}

/// Check if the request is a WebSocket upgrade request.
fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    // Check for Upgrade: websocket header
    let has_upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("websocket"))
        .unwrap_or(false);

    // Check for Connection: upgrade header
    let has_connection_upgrade = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    has_upgrade && has_connection_upgrade
}

/// Handle incoming requests, routing WebSocket upgrades separately.
async fn handle_request(
    req: Request<Incoming>,
    backend_addr: String,
    client: Arc<HttpClient>,
    peer_addr: SocketAddr,
    max_body_size: usize,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    if is_websocket_upgrade(&req) {
        handle_websocket_upgrade(req, &backend_addr).await
    } else {
        proxy_request(req, &backend_addr, client, peer_addr, max_body_size).await
    }
}

/// Handle WebSocket upgrade requests.
async fn handle_websocket_upgrade(
    req: Request<Incoming>,
    backend_addr: &str,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    // Extract the path for the backend connection
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Validate path to prevent HTTP request smuggling and header injection
    // Reject paths containing control characters or whitespace that could be used for injection
    if path.contains('\r')
        || path.contains('\n')
        || path.contains('\0')
        || path.contains('\t')
        || path.contains(' ')
    {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "Invalid path (contains control characters or whitespace)",
        ));
    }

    // Get the WebSocket key from the request
    let ws_key = match req.headers().get(SEC_WEBSOCKET_KEY) {
        Some(key) => key.clone(),
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing Sec-WebSocket-Key",
            ));
        }
    };

    // Connect to the backend
    let backend_stream = match TcpStream::connect(backend_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("WebSocket backend connection failed: {}", e);
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                format!("Backend connection failed: {}", e),
            ));
        }
    };

    // Build the WebSocket upgrade request for the backend
    let mut upgrade_request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n",
        path,
        backend_addr,
        ws_key.to_str().unwrap_or("")
    );

    // Forward other WebSocket-related headers (validate to prevent CRLF injection)
    for (name, value) in req.headers().iter() {
        let name_str = name.as_str();
        let name_lower = name_str.to_lowercase();
        if name_lower.starts_with("sec-websocket-") && name_lower != "sec-websocket-key" {
            if let Ok(v) = value.to_str() {
                // Skip headers with control characters in BOTH name and value to prevent injection
                if !name_str.contains('\r')
                    && !name_str.contains('\n')
                    && !name_str.contains('\0')
                    && !v.contains('\r')
                    && !v.contains('\n')
                    && !v.contains('\0')
                {
                    upgrade_request.push_str(&format!("{}: {}\r\n", name_str, v));
                }
            }
        }
    }
    upgrade_request.push_str("\r\n");

    // Send upgrade request to backend
    let (mut backend_read, mut backend_write) = backend_stream.into_split();
    if let Err(e) = backend_write.write_all(upgrade_request.as_bytes()).await {
        eprintln!("Failed to send WebSocket upgrade to backend: {}", e);
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "Backend write failed",
        ));
    }

    // Read backend response headers
    // Use a growable buffer to avoid truncating large headers
    let mut response_buf = Vec::with_capacity(WEBSOCKET_BUFFER_SIZE);
    let mut temp_buf = [0u8; 4096];

    // Read until we find end of headers (\r\n\r\n) or reach max size
    loop {
        let n = match backend_read.read(&mut temp_buf).await {
            Ok(n) if n > 0 => n,
            Ok(_) => {
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "Backend closed connection",
                ));
            }
            Err(e) => {
                eprintln!("Failed to read WebSocket upgrade response: {}", e);
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "Backend read failed",
                ));
            }
        };

        response_buf.extend_from_slice(&temp_buf[..n]);

        // Check if we've received the end of headers
        if response_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        // Prevent unbounded growth
        if response_buf.len() >= MAX_WEBSOCKET_HEADER_SIZE {
            eprintln!("WebSocket upgrade response headers exceed maximum size");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Response headers too large",
            ));
        }
    }

    // Parse the response to check if upgrade was accepted
    // Must be "HTTP/1.1 101" at the start of the status line
    let response_str = String::from_utf8_lossy(&response_buf);
    let is_101_switching = response_str.lines().next().is_some_and(|line| {
        let line = line.trim();
        line.starts_with("HTTP/1.1 101") || line.starts_with("HTTP/1.0 101")
    });

    if !is_101_switching {
        eprintln!("Backend rejected WebSocket upgrade: {}", response_str);
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "Backend rejected WebSocket upgrade",
        ));
    }

    // Extract Sec-WebSocket-Accept from backend response
    let accept_key = response_str
        .lines()
        .find(|line| line.to_lowercase().starts_with("sec-websocket-accept:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|v| v.trim().to_string());

    // Build the upgrade response for the client
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade");

    if let Some(accept) = accept_key {
        response = response.header(SEC_WEBSOCKET_ACCEPT, accept);
    }

    // Spawn the bidirectional relay task
    tokio::task::spawn(async move {
        // Reunite the backend stream halves immediately so we can clean up properly
        let mut backend_stream = match backend_read.reunite(backend_write) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("WebSocket backend stream reunite failed: {:?}", e);
                return;
            }
        };

        // hyper's upgrade mechanism - get the upgraded IO
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);

                // Relay data bidirectionally
                let (mut client_read, mut client_write) = tokio::io::split(&mut client_io);
                let (mut backend_read, mut backend_write) = tokio::io::split(&mut backend_stream);

                let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
                let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);

                tokio::select! {
                    result = client_to_backend => {
                        if let Err(e) = result {
                            if e.kind() != std::io::ErrorKind::ConnectionReset {
                                eprintln!("WebSocket client->backend error: {}", e);
                            }
                        }
                    }
                    result = backend_to_client => {
                        if let Err(e) = result {
                            if e.kind() != std::io::ErrorKind::ConnectionReset {
                                eprintln!("WebSocket backend->client error: {}", e);
                            }
                        }
                    }
                }
                // Explicitly shutdown the backend connection
                let _ = backend_stream.shutdown().await;
            }
            Err(e) => {
                eprintln!("WebSocket upgrade failed: {}", e);
                // Explicitly shutdown the backend connection on failure
                let _ = backend_stream.shutdown().await;
            }
        }
    });

    Ok(response.body(Full::new(Bytes::new())).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from("Failed to build response")))
            .unwrap()
    }))
}

/// Run the HTTP-to-HTTPS redirect server.
async fn run_redirect_server(
    listener: TcpListener,
    config: RedirectConfig,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // Connection limiter for redirect server
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // Track connection tasks for graceful shutdown
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                // Wait for in-flight connections with timeout
                let active_count = connection_tasks.len();
                if active_count > 0 {
                    let drain_result = tokio::time::timeout(
                        GRACEFUL_SHUTDOWN_TIMEOUT,
                        drain_connections(&mut connection_tasks)
                    ).await;

                    if drain_result.is_err() {
                        connection_tasks.abort_all();
                    }
                }
                return;
            }

            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, peer_addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("HTTP redirect accept error: {}", e);
                        continue;
                    }
                };

                // Acquire permit from semaphore
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!(
                            "Redirect connection limit reached, rejecting connection from {}",
                            peer_addr
                        );
                        drop(stream);
                        continue;
                    }
                };

                let config = config.clone();
                connection_tasks.spawn(async move {
                    let _permit = permit;

                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let config = config.clone();
                        async move { handle_redirect(req, config) }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        if !e.to_string().contains("connection closed") {
                            eprintln!("HTTP redirect connection error: {}", e);
                        }
                    }
                });

                // Clean up completed tasks
                while connection_tasks.try_join_next().is_some() {}
            }
        }
    }
}

/// Handle an HTTP request by redirecting to HTTPS.
fn handle_redirect(
    req: Request<Incoming>,
    config: RedirectConfig,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Build the HTTPS URL
    let https_url = if config.https_port == 443 {
        format!("https://{}{}", config.host, path)
    } else {
        format!("https://{}:{}{}", config.host, config.https_port, path)
    };

    Ok(Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY) // 301 redirect
        .header("Location", &https_url)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<p>Redirecting to <a href="{url}">{url}</a></p>
</body>
</html>"#,
            url = https_url
        ))))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Failed to build response")))
                .unwrap()
        }))
}

async fn proxy_request(
    req: Request<Incoming>,
    backend_addr: &str,
    client: Arc<HttpClient>,
    peer_addr: SocketAddr,
    max_body_size: usize,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = format!(
        "http://{}{}",
        backend_addr,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    // Check Content-Length header first for early rejection
    if let Some(content_length) = req.headers().get(CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > max_body_size {
                    eprintln!(
                        "Request rejected: body size {} exceeds limit {}",
                        length, max_body_size
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(Bytes::from(format!(
                            "Request body too large. Maximum size is {} bytes.",
                            max_body_size
                        ))))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
                }
            }
        }
    }

    // Extract original host before consuming the request
    let original_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let (parts, body) = req.into_parts();

    // Use Limited to enforce body size limit (protects against chunked encoding without Content-Length)
    let limited_body = Limited::new(body, max_body_size);
    let body_bytes = match limited_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            eprintln!(
                "Request rejected: chunked body exceeds limit {}",
                max_body_size
            );
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::from(format!(
                    "Request body too large. Maximum size is {} bytes.",
                    max_body_size
                ))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
    };

    let mut backend_req = Request::builder().method(parts.method).uri(&uri);
    for (name, value) in parts.headers.iter() {
        // Skip headers we'll set ourselves
        let name_lower = name.as_str().to_lowercase();
        if name != hyper::header::HOST
            && !name_lower.starts_with("x-forwarded-")
            && name_lower != "x-real-ip"
        {
            backend_req = backend_req.header(name, value);
        }
    }
    // Use original host for Host header (strip port for proper app routing)
    let host_without_port = original_host.split(':').next().unwrap_or("localhost");
    backend_req = backend_req.header(hyper::header::HOST, host_without_port);

    // Add standard proxy headers so backends know the original request was HTTPS
    backend_req = backend_req.header("X-Forwarded-Proto", "https");
    backend_req = backend_req.header("X-Forwarded-For", peer_addr.ip().to_string());
    backend_req = backend_req.header("X-Forwarded-Host", original_host);
    backend_req = backend_req.header("X-Real-IP", peer_addr.ip().to_string());

    let backend_req = match backend_req.body(Full::new(body_bytes)) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Failed to build request: {}", e);
            return Ok(Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal error")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
    };

    match client.request(backend_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            // Limit response body size to prevent memory exhaustion
            let limited_body = Limited::new(body, max_body_size);
            match limited_body.collect().await {
                Ok(collected) => {
                    let body_bytes = collected.to_bytes();
                    Ok(Response::from_parts(parts, Full::new(body_bytes)))
                }
                Err(_) => {
                    eprintln!("Response rejected: body exceeds limit {}", max_body_size);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!(
                            "Response body too large. Maximum size is {} bytes.",
                            max_body_size
                        ))))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
                }
            }
        }
        Err(e) => {
            eprintln!("Backend error: {}", e);
            Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("Backend error: {}", e))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
        }
    }
}

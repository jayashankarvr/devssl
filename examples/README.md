# devssl Examples

This directory contains configuration examples for using devssl with popular frameworks and tools.

## Quick Start

1. Initialize devssl (one-time setup):

   ```bash
   devssl init
   ```

2. Choose your framework below and follow the instructions.

## Frameworks

| Framework | Description |
| --------- | ----------- |
| [Express.js](express/) | Node.js Express with HTTPS |
| [Next.js](nextjs/) | Next.js development server |
| [Vite](vite/) | Vite dev server (Vue, React, Svelte) |
| [Flask](flask/) | Python Flask with SSL context |
| [Django](django/) | Django development server |
| [Rails](rails/) | Ruby on Rails with Puma |
| [Actix-web](rust-actix/) | Rust Actix-web TLS |
| [Docker](docker/) | Docker Compose with HTTPS |

## Using the Proxy (Easiest Method)

For any framework, you can use devssl's built-in proxy instead of configuring HTTPS directly:

```bash
# Start your app on HTTP (e.g., port 3000)
npm run dev  # or your framework's dev command

# In another terminal, start the HTTPS proxy
devssl proxy 3000
```

Then access your app at `https://localhost:3000`.

### Proxy Options

```bash
# Mobile/VM testing (bind to all interfaces)
devssl proxy 3000 --bind 0.0.0.0

# Custom HTTPS port
devssl proxy 3000 --https-port 8443

# HTTP to HTTPS redirect
devssl proxy 3000 --redirect

# Skip backend check (for hot-reload scenarios)
devssl proxy 3000 --skip-check
```

## Environment Variables

After running `devssl init`, you can use these environment variables in your app:

```bash
# Show certificate paths
devssl path

# Export for use in scripts
export SSL_CERT_FILE=$(devssl path | grep 'Certificate:' | awk '{print $2}')
export SSL_KEY_FILE=$(devssl path | grep 'Key:' | awk '{print $2}')
```

## Node.js Applications

For Node.js apps, you may need to trust the CA:

```bash
# Show the NODE_EXTRA_CA_CERTS export command
devssl init --node

# Or manually
export NODE_EXTRA_CA_CERTS=$(devssl path | grep 'CA certificate:' | awk '{print $3}')
```

## Mobile Testing

To test on mobile devices:

1. Bind to all interfaces: `devssl proxy 3000 --bind 0.0.0.0`
2. Install CA on your device: `devssl qr`
3. Scan the QR code and install the certificate profile

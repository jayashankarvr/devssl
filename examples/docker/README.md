# Docker with devssl

## Option 1: Using the Proxy (Host-side)

Run devssl proxy on the host, forward to container:

```bash
# Start your container
docker run -p 3000:3000 myapp

# Start HTTPS proxy on host
devssl proxy 3000
```

Access at `https://localhost:3000`.

## Option 2: Mount Certificates

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    volumes:
      # Mount devssl certificates (read-only)
      - ~/.local/share/devssl/localhost.crt:/app/certs/localhost.crt:ro
      - ~/.local/share/devssl/localhost.key:/app/certs/localhost.key:ro
      - ~/.local/share/devssl/ca.crt:/app/certs/ca.crt:ro
    environment:
      - SSL_CERT_FILE=/app/certs/localhost.crt
      - SSL_KEY_FILE=/app/certs/localhost.key
      - NODE_EXTRA_CA_CERTS=/app/certs/ca.crt
```

### Generate Config Snippet

```bash
devssl docker-compose
```

This outputs a ready-to-use volume mount configuration.

## Option 3: Build with Certificates

### Dockerfile

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Copy certificates (for development only!)
COPY certs/ /app/certs/

ENV SSL_CERT_FILE=/app/certs/localhost.crt
ENV SSL_KEY_FILE=/app/certs/localhost.key

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
```

### Build

```bash
# Export certificates to a local directory
mkdir -p certs
cp ~/.local/share/devssl/localhost.* certs/
cp ~/.local/share/devssl/ca.crt certs/

# Build image
docker build -t myapp .
```

## Trusting the CA in Container

For containers that need to trust the devssl CA (for curl, wget, etc.):

```dockerfile
# Debian/Ubuntu
COPY ca.crt /usr/local/share/ca-certificates/devssl.crt
RUN update-ca-certificates

# Alpine
COPY ca.crt /usr/local/share/ca-certificates/devssl.crt
RUN cat /usr/local/share/ca-certificates/devssl.crt >> /etc/ssl/certs/ca-certificates.crt
```

## Installing devssl in Alpine Container

```dockerfile
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache ca-certificates curl

# Download devssl binary
RUN curl -fsSL https://github.com/jayashankarvr/devssl/releases/latest/download/devssl-linux-musl-x64.tar.gz \
    | tar -xz -C /usr/local/bin

# Initialize (CI mode - no trust store installation)
RUN devssl init --ci
```

For browser support inside containers (rare), add `nss-tools`:

```dockerfile
RUN apk add --no-cache nss-tools
```

## Security Note

Never include development certificates in production images. Use multi-stage builds or separate Dockerfiles for development and production.

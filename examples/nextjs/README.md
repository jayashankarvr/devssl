# Next.js with devssl

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Start Next.js normally
npm run dev  # Runs on http://localhost:3000

# Terminal 2: Start HTTPS proxy
devssl proxy 3000
```

Access at `https://localhost:3000`.

## Option 2: Custom Server

Create a custom server with HTTPS support.

### next.config.js

```javascript
module.exports = {
  // Your existing config
};
```

### server.js

```javascript
const https = require('https');
const fs = require('fs');
const { parse } = require('url');
const next = require('next');

const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();

const certPath = process.env.SSL_CERT_FILE ||
  `${process.env.HOME}/.local/share/devssl/localhost.crt`;
const keyPath = process.env.SSL_KEY_FILE ||
  `${process.env.HOME}/.local/share/devssl/localhost.key`;

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

app.prepare().then(() => {
  https.createServer(options, (req, res) => {
    const parsedUrl = parse(req.url, true);
    handle(req, res, parsedUrl);
  }).listen(3000, () => {
    console.log('> Ready on https://localhost:3000');
  });
});
```

### Run

```bash
devssl init
export NODE_EXTRA_CA_CERTS=~/.local/share/devssl/ca.crt
node server.js
```

## Environment Variables

```bash
# For Node.js to trust the CA
export NODE_EXTRA_CA_CERTS=~/.local/share/devssl/ca.crt
```

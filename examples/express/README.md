# Express.js with devssl

## Option 1: Using the Proxy (Recommended)

The easiest approach - no code changes needed:

```bash
# Terminal 1: Start your Express app normally
node app.js  # Listening on http://localhost:3000

# Terminal 2: Start HTTPS proxy
devssl proxy 3000
```

Access at `https://localhost:3000`.

## Option 2: Native HTTPS

Use the provided `server.js` as a reference:

```bash
# Initialize devssl
devssl init

# Install dependencies
npm install express

# Set certificate paths
export SSL_CERT_FILE=~/.local/share/devssl/localhost.crt
export SSL_KEY_FILE=~/.local/share/devssl/localhost.key

# Run the server
node server.js
```

## Key Code

```javascript
const https = require('https');
const fs = require('fs');

const certPath = process.env.SSL_CERT_FILE;
const keyPath = process.env.SSL_KEY_FILE;

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

https.createServer(options, app).listen(3000);
```

## Troubleshooting

If you see certificate errors in Node.js, trust the devssl CA:

```bash
export NODE_EXTRA_CA_CERTS=~/.local/share/devssl/ca.crt
node server.js
```

// Express.js HTTPS Server with devssl
//
// Usage:
//   1. Run: devssl init
//   2. Set environment variables (see below)
//   3. Run: node server.js
//   4. Open: https://localhost:3000
//
// Environment setup:
//   export SSL_CERT_FILE=~/.local/share/devssl/localhost.crt
//   export SSL_KEY_FILE=~/.local/share/devssl/localhost.key
//
// Or use: eval $(devssl path --export)

const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

app.get('/', (req, res) => {
  res.send('Hello from HTTPS!');
});

// Get certificate paths from environment or default locations
const certPath = process.env.SSL_CERT_FILE ||
  `${process.env.HOME}/.local/share/devssl/localhost.crt`;
const keyPath = process.env.SSL_KEY_FILE ||
  `${process.env.HOME}/.local/share/devssl/localhost.key`;

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.error('Error: Certificates not found.');
  console.error('Run "devssl init" first, then set SSL_CERT_FILE and SSL_KEY_FILE.');
  process.exit(1);
}

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

https.createServer(options, app).listen(3000, () => {
  console.log('HTTPS server running at https://localhost:3000');
});

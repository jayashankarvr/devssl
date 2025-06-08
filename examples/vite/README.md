# Vite with devssl

Works with Vue, React, Svelte, and other Vite-based projects.

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Start Vite normally
npm run dev  # Runs on http://localhost:5173

# Terminal 2: Start HTTPS proxy
devssl proxy 5173
```

Access at `https://localhost:5173`.

## Option 2: Vite Configuration

### vite.config.js

```javascript
import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

// Get devssl paths
const certDir = process.env.HOME + '/.local/share/devssl';

export default defineConfig({
  server: {
    https: {
      key: fs.readFileSync(path.join(certDir, 'localhost.key')),
      cert: fs.readFileSync(path.join(certDir, 'localhost.crt')),
    },
    host: 'localhost',
    port: 5173,
  },
});
```

### Run

```bash
devssl init
npm run dev
```

## With Custom Domain

```bash
# Generate certificate for custom domain
devssl generate myapp.local

# Update vite.config.js to use myapp.local.crt and myapp.local.key
```

Add to `/etc/hosts`:

```txt
127.0.0.1 myapp.local
```

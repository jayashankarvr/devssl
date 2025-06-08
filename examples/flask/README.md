# Flask with devssl

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Start Flask normally
flask run --port 5000

# Terminal 2: Start HTTPS proxy
devssl proxy 5000
```

Access at `https://localhost:5000`.

## Option 2: Native SSL

### app.py

```python
from flask import Flask
import os
import ssl

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from HTTPS!'

if __name__ == '__main__':
    # Get certificate paths
    cert_dir = os.path.expanduser('~/.local/share/devssl')
    cert_path = os.environ.get('SSL_CERT_FILE', f'{cert_dir}/localhost.crt')
    key_path = os.environ.get('SSL_KEY_FILE', f'{cert_dir}/localhost.key')

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    app.run(host='127.0.0.1', port=5000, ssl_context=context)
```

### Run

```bash
devssl init
python app.py
```

## With Gunicorn

```bash
gunicorn --certfile ~/.local/share/devssl/localhost.crt \
         --keyfile ~/.local/share/devssl/localhost.key \
         --bind 127.0.0.1:5000 \
         app:app
```

## Trusting the CA

For requests to work with the devssl CA:

```python
import os
os.environ['REQUESTS_CA_BUNDLE'] = os.path.expanduser('~/.local/share/devssl/ca.crt')
```

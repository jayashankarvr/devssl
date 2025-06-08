# Django with devssl

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Start Django normally
python manage.py runserver 8000

# Terminal 2: Start HTTPS proxy
devssl proxy 8000
```

Access at `https://localhost:8000`.

## Option 2: Django Extensions

Install django-extensions for SSL support:

```bash
pip install django-extensions Werkzeug pyOpenSSL
```

### settings.py

Add to INSTALLED_APPS:

```python
INSTALLED_APPS = [
    # ...
    'django_extensions',
]
```

### Run

```bash
devssl init

python manage.py runserver_plus --cert-file ~/.local/share/devssl/localhost.crt \
                                 --key-file ~/.local/share/devssl/localhost.key \
                                 127.0.0.1:8000
```

## Option 3: Gunicorn

```bash
gunicorn --certfile ~/.local/share/devssl/localhost.crt \
         --keyfile ~/.local/share/devssl/localhost.key \
         --bind 127.0.0.1:8000 \
         myproject.wsgi:application
```

## HTTPS Settings

Add to `settings.py` for HTTPS in development:

```python
if DEBUG:
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
```

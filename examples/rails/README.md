# Ruby on Rails with devssl

## Option 1: Using the Proxy (Recommended)

No configuration needed:

```bash
# Terminal 1: Start Rails normally
rails server -p 3000

# Terminal 2: Start HTTPS proxy
devssl proxy 3000
```

Access at `https://localhost:3000`.

## Option 2: Puma Configuration

### config/puma.rb

```ruby
# Only enable SSL in development
if ENV['RAILS_ENV'] == 'development' || ENV.fetch('RAILS_ENV', 'development') == 'development'
  cert_dir = File.expand_path('~/.local/share/devssl')
  cert_path = ENV['SSL_CERT_FILE'] || File.join(cert_dir, 'localhost.crt')
  key_path = ENV['SSL_KEY_FILE'] || File.join(cert_dir, 'localhost.key')

  if File.exist?(cert_path) && File.exist?(key_path)
    ssl_bind '127.0.0.1', '3000', {
      key: key_path,
      cert: cert_path,
      verify_mode: 'none'
    }
  end
end
```

### Run

```bash
devssl init
rails server
```

## Option 3: Environment Variables

```bash
# In .env or shell
export SSL_CERT_FILE=~/.local/share/devssl/localhost.crt
export SSL_KEY_FILE=~/.local/share/devssl/localhost.key

# Run with binding
rails server -b 'ssl://127.0.0.1:3000?key=$SSL_KEY_FILE&cert=$SSL_CERT_FILE'
```

## Force SSL in Development

In `config/environments/development.rb`:

```ruby
# Uncomment to force SSL in development
# config.force_ssl = true
```

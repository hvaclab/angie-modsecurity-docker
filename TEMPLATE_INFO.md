# Angie Web Server Template - Information

## Overview

This is a clean, production-ready template for Angie web server with multi-layered security. All configuration files use example values and are ready for customization.

## Template Structure

```
angie-modsecurity-docker/
├── README.md                    # Comprehensive documentation
├── TEMPLATE_INFO.md            # This file
├── SECURITY_CHECKLIST.md       # Security best practices
├── .env.example                # Template environment variables
├── .gitignore                  # Git ignore patterns
├── compose.yml                 # Docker Compose configuration
│
├── angie/                      # Angie configuration
│   ├── angie.conf
│   ├── Dockerfile
│   ├── conf.d/
│   │   ├── default.conf
│   │   ├── example.com.conf              # Static site example
│   │   ├── proxy-example.com.conf        # Reverse proxy example
│   │   ├── example-upstream.conf.disabled
│   │   └── monitoring.conf.example
│   ├── includes/               # Reusable configs
│   │   ├── auth/              # OAuth2/Keycloak
│   │   ├── security/          # Headers, SSL, rate limiting
│   │   ├── logs/              # Log enrichment
│   │   ├── performance/       # Compression, caching
│   │   └── monitoring/        # VTS metrics
│   └── stream.d/              # TCP/UDP configs
│
├── certs/                      # SSL certificates (empty)
│   └── .gitkeep
│
├── logs/                       # Logs (empty)
│   └── .gitkeep
│
├── geoip/                      # GeoIP databases (empty)
│   └── .gitkeep
│
├── fail2ban/                   # Fail2Ban configuration
│   ├── filter.d/              # Log filters
│   ├── jail.d/                # Jail configurations
│   └── db/                    # Database (empty)
│       └── .gitkeep
│
├── modsec/                     # ModSecurity WAF
│   ├── rules.conf
│   └── exclusions.conf
│
├── vector/                     # Vector log pipeline
│   └── vector.toml
│
├── web/                        # Static website placeholder
│   ├── index.html
│   ├── robots.txt
│   └── protected-path/
│
├── scripts/                    # Utility scripts
│   ├── rotate-logs.sh
│   ├── check-ssl-expiry.sh
│   └── test-rate-limiting.sh
│
└── errors/                     # Custom error pages
    ├── 403.html
    ├── 404.html
    └── 502.html
```

## Quick Start

### 1. Copy Template to Your Project

```bash
cp -r angie-modsecurity-docker /path/to/your-project
cd /path/to/your-project
```

### 2. Configure Environment

```bash
# Create environment file
cp .env.example .env

# Edit with your settings
nano .env
```

### 3. Configure Domain

```bash
cd angie/conf.d

# Copy example configuration
cp example.com.conf yourdomain.com.conf

# Edit configuration
nano yourdomain.com.conf
# Replace 'example.com' with your actual domain
```

### 4. Generate Certificates

```bash
# DH parameters (takes a few minutes)
openssl dhparam -out certs/dhparam.pem 2048

# Self-signed certificate for default server
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/default-selfsigned.key \
  -out certs/default-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=default"
```

### 5. Download GeoIP (Optional)

```bash
cd geoip
curl -L "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" -o GeoLite2-Country.mmdb
curl -L "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" -o GeoLite2-City.mmdb
cd ..
```

### 6. Start Services

```bash
docker compose up -d
```

## Features Included

### Security (Multi-layered)
- ModSecurity WAF with OWASP CRS 4.18.0 (825+ rules)
- Fail2Ban with 4 jail configurations
- Rate limiting (DDoS protection)
- Automatic SSL/TLS (built-in ACME client)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- HTTP/2 and HTTP/3 (QUIC) support

### Monitoring & Analytics
- Rich log enrichment (70+ fields)
- Vector log pipeline
- GeoIP support (country, city, coordinates)
- User-Agent analysis (browser, OS, device)
- Security scoring (0-15)
- Performance metrics

### Authentication (Optional)
- OAuth2/OIDC support (oauth2-proxy)
- Keycloak integration ready
- Protected paths configuration

### Configuration Examples
- Static website hosting
- Reverse proxy to backend applications
- ModSecurity rule customization
- Rate limiting configuration
- Custom error pages

## What to Configure

### Required
1. `.env` - Your email and domain settings
2. `angie/conf.d/yourdomain.com.conf` - Virtual host configuration
3. `certs/` - Generate self-signed certificates (see Quick Start)

### Optional
1. `geoip/` - Download GeoIP databases
2. `modsec/exclusions.conf` - ModSecurity rule exclusions
3. `fail2ban/jail.d/angie.conf` - Customize ban times
4. `.env` - Keycloak settings (if using authentication)
5. `angie/includes/auth/keycloak-protected-paths.conf` - Protected paths

## Verification Checklist

Before deploying:

- [ ] Created `.env` from `.env.example`
- [ ] Updated email address in `.env`
- [ ] Configured domain in virtual host
- [ ] Generated DH parameters and self-signed certificates
- [ ] Set `LETSENCRYPT_STAGING=1` for testing
- [ ] Tested configuration: `docker exec angie angie -t`
- [ ] Downloaded GeoIP databases (optional)
- [ ] Reviewed security settings
- [ ] Configured backups for ACME certificates
- [ ] Set up log rotation (cron job)

## Support & Documentation

- **Angie Documentation**: https://angie.software/en/
- **ModSecurity**: https://github.com/SpiderLabs/ModSecurity
- **OWASP CRS**: https://coreruleset.org/

## License

MIT License - Free to use and modify

---

**Template Version**: 1.0.0

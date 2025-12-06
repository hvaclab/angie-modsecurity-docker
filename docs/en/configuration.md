# Configuration Guide

This document describes how to configure the integrated angie-modsecurity-docker stack for your specific needs.

## Quick Start

### 1. Environment Variables

Create `.env` file from example:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Timezone
TZ=Europe/Moscow

# Keycloak Configuration (if using OAuth2)
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=myrealm
KEYCLOAK_CLIENT_ID=angie-client
KEYCLOAK_CLIENT_SECRET=your-secret-here
KEYCLOAK_REDIRECT_URI=https://example.com/oauth2/callback
KEYCLOAK_COOKIE_SECRET=generate-random-32-chars
KEYCLOAK_COOKIE_NAME=_oauth2_proxy
```

Generate cookie secret:
```bash
python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

### 2. Virtual Host Configuration

Create your virtual host in `angie/conf.d/yourdomain.com.conf`:

```nginx
server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;

    server_name yourdomain.com;

    # ACME for Let's Encrypt
    acme letsencrypt;
    ssl_certificate     $acme_cert_letsencrypt;
    ssl_certificate_key $acme_cert_key_letsencrypt;

    # HTTP/3 announcement
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    # Security headers
    include /etc/angie/includes/security/security-headers.conf;

    # ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;

    root /var/www/html;

    location / {
        limit_req zone=general burst=20 nodelay;
        try_files $uri $uri/ =404;
    }

    location ~* \.(jpg|jpeg|png|gif|css|js)$ {
        limit_req zone=static burst=100 nodelay;
        expires 30d;
    }
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}
```

### 3. Start the Stack

```bash
docker compose up -d
```

## Component Configuration

### Angie Web Server

#### Main Configuration

File: `angie/angie.conf`

```nginx
# Load required modules
load_module modules/ngx_http_modsecurity_module.so;
load_module modules/ngx_http_geoip2_module.so;
load_module modules/ngx_http_brotli_filter_module.so;

user angie;
worker_processes auto;

http {
    # Include reusable configs
    include /etc/angie/includes/security/headers-advanced.conf;
    include /etc/angie/includes/security/rate-limiting.conf;
    include /etc/angie/includes/logs/enrichment.conf;
    include /etc/angie/includes/logs/log-formats.conf;

    # DNS resolver for Docker
    resolver 127.0.0.11 valid=10s ipv6=off;

    # Logging
    access_log /var/log/angie/access.log json_enriched buffer=64k flush=5s;
    error_log /var/log/angie/error.log warn;

    # Include virtual hosts
    include /etc/angie/conf.d/*.conf;
}
```

#### Rate Limiting Zones

File: `angie/includes/security/rate-limiting.conf`

Adjust rates based on your traffic:

```nginx
# General traffic (adjust rate based on your needs)
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

# Static files (browsers load many in parallel)
limit_req_zone $binary_remote_addr zone=static:10m rate=50r/s;

# API endpoints (stricter)
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;

# Forms (prevent spam)
limit_req_zone $binary_remote_addr zone=forms:10m rate=2r/s;
```

Usage in locations:
```nginx
location /api/ {
    limit_req zone=api burst=10 nodelay;
    # ... rest of config
}

location /contact-form {
    limit_req zone=forms burst=3 nodelay;
    # ... rest of config
}
```

#### SSL/TLS Configuration

File: `angie/includes/security/ssl-params.conf`

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;
ssl_prefer_server_ciphers off;

# Session cache
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

# DH parameters
ssl_dhparam /etc/ssl/certs/dhparam.pem;
```

### ModSecurity WAF

#### Basic Configuration

File: `modsec/rules.conf`

```
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Temp directories
SecDataDir /tmp/
SecTmpDir /tmp/

# OWASP CRS
Include /var/lib/angie/modsecurity/coreruleset/crs-setup.conf
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf

# Custom exclusions
Include /etc/angie/modsecurity/exclusions.conf
```

#### Custom Exclusions

File: `modsec/exclusions.conf`

```
# Example: Disable specific rule for upload endpoint
SecRule REQUEST_URI "@beginsWith /api/upload" \
    "id:1001,phase:1,pass,nolog,ctl:ruleRemoveById=920420"

# Example: Increase body limit for specific API
SecRule REQUEST_URI "@beginsWith /api/data/bulk" \
    "id:1002,phase:1,pass,nolog,ctl:requestBodyLimit=10485760"

# Example: Completely disable WAF for health checks
SecRule REQUEST_URI "@streq /health" \
    "id:1003,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

#### Paranoia Levels

The CRS uses paranoia levels (1-4) to control strictness:

```
# In CRS configuration file (mounted from host)
SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.paranoia_level=1"

# Level 1: Basic protection (default, recommended)
# Level 2: More rules, some false positives
# Level 3: Strict, many false positives
# Level 4: Very strict, high maintenance
```

### Fail2Ban

#### Jail Configuration

File: `fail2ban/jail.d/angie.conf`

Adjust thresholds based on your environment:

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16
# Add your trusted IPs:
# ignoreip = 127.0.0.1/8 203.0.113.50

# ModSecurity violations
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3       # Adjust: how many violations before ban
findtime = 300     # Adjust: time window (5 minutes)
bantime = 7200     # Adjust: ban duration (2 hours)
action = iptables-allports[name=angie-modsec]

# Scanner detection
[angie-scan]
enabled = true
filter = angie-scan
logpath = /var/log/angie/access.log
maxretry = 10      # Adjust: suspicious 404s
findtime = 600     # Adjust: time window (10 minutes)
bantime = 86400    # Adjust: ban duration (24 hours)
action = iptables-allports[name=angie-scan]

# DDoS protection
[angie-ddos]
enabled = true
filter = angie-ddos
logpath = /var/log/angie/access.log
maxretry = 100     # Adjust: based on legitimate traffic
findtime = 60      # Adjust: time window (1 minute)
bantime = 600      # Adjust: ban duration (10 minutes)
action = iptables-allports[name=angie-ddos]
```

#### Custom Filters

Create custom filter in `fail2ban/filter.d/custom.conf`:

```ini
[Definition]
# Example: Block on multiple 403 errors
failregex = "client_ip":"<HOST>".*"response_status":"403"
ignoreregex =
```

Add jail:
```ini
[custom-403]
enabled = true
filter = custom
logpath = /var/log/angie/access.log
maxretry = 5
findtime = 300
bantime = 3600
```

### OAuth2-Proxy Authentication

#### Environment Configuration

In `.env`:

```bash
# Keycloak OIDC settings
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=production
KEYCLOAK_CLIENT_ID=angie-webapp
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=https://example.com/oauth2/callback

# Session security
KEYCLOAK_COOKIE_SECRET=random-32-byte-string-base64
KEYCLOAK_COOKIE_NAME=_oauth2_proxy

# Optional: Restrict email domains
OAUTH2_PROXY_EMAIL_DOMAINS=example.com,partner.com
```

#### Angie Integration

File: `angie/includes/auth/keycloak-auth.conf` (already included)

Usage in virtual host:

```nginx
server {
    # ... SSL and other config ...

    # Include OAuth2-Proxy endpoints
    include /etc/angie/includes/auth/keycloak-auth.conf;

    # Protect specific paths
    location /admin {
        # Require authentication
        auth_request /oauth2/auth;
        error_page 401 = @oauth2_signin;

        # Extract user info
        auth_request_set $user $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;
        auth_request_set $groups $upstream_http_x_auth_request_groups;

        # Pass to backend
        proxy_set_header X-User $user;
        proxy_set_header X-Email $email;
        proxy_set_header X-Groups $groups;

        proxy_pass http://admin-backend:8080;
    }

    # Public paths (no auth)
    location / {
        root /var/www/html;
    }
}
```

#### Protected Paths Configuration

File: `angie/includes/auth/keycloak-protected-paths.conf`

```nginx
# Protect admin panel
location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-User $user;

    proxy_pass http://backend:8080;
}

# Protect API
location /api/private {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    auth_request_set $email $upstream_http_x_auth_request_email;
    proxy_set_header X-Email $email;

    proxy_pass http://api:8080;
}
```

### Vector Log Pipeline

#### Basic Configuration

File: `vector/vector.toml`

```toml
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]
read_from = "end"  # Change to "beginning" to process existing logs

[transforms.parse_json]
type = "remap"
inputs = ["angie_logs"]
source = '''
  . = parse_json!(.message)

  # Add metadata
  .meta_enriched_by = "vector"
  .meta_enriched_at = now()

  # Calculate security score
  score = 0
  if .security_suspicious_ua == "1" { score = score + 5 }
  if .security_suspicious_pattern == "1" { score = score + 7 }
  if .security_suspicious_xff == "1" { score = score + 3 }
  .security_score = score

  # Classify threat level
  .security_threat_level = if score == 0 { "safe" }
                           else if score < 5 { "low" }
                           else if score < 10 { "medium" }
                           else { "high" }
'''

[sinks.enriched_logs]
type = "file"
inputs = ["parse_json"]
path = "/var/log/angie/access_enriched.log"
encoding.codec = "json"
```

#### Advanced: Send to External System

```toml
# Send to Loki
[sinks.loki]
type = "loki"
inputs = ["parse_json"]
endpoint = "http://loki:3100"
encoding.codec = "json"
labels.job = "angie"
labels.environment = "production"

# Send to Elasticsearch
[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["parse_json"]
endpoint = "http://elasticsearch:9200"
index = "angie-logs-%Y.%m.%d"

# Send to Kafka
[sinks.kafka]
type = "kafka"
inputs = ["parse_json"]
bootstrap_servers = "kafka:9092"
topic = "angie-logs"
encoding.codec = "json"
```

## Common Scenarios

### Scenario 1: High-Traffic Website

Adjust rate limits:

```nginx
# Increase general limit
limit_req_zone $binary_remote_addr zone=general:20m rate=50r/s;
limit_req zone=general burst=100 nodelay;

# Increase static files limit
limit_req_zone $binary_remote_addr zone=static:20m rate=200r/s;
limit_req zone=static burst=300 nodelay;
```

Adjust Fail2Ban:

```ini
[angie-ddos]
maxretry = 500     # Higher threshold
findtime = 60
bantime = 300      # Shorter ban time
```

### Scenario 2: API Server

Create API-specific rate limit:

```nginx
# Strict API rate limiting
limit_req_zone $binary_remote_addr zone=api_public:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_authenticated:10m rate=100r/s;

# Map to determine which zone
map $http_authorization $api_zone {
    default "api_public";
    ~^Bearer api_authenticated;
}

location /api/ {
    limit_req zone=$api_zone burst=20 nodelay;

    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;

    proxy_pass http://api-backend:8080;
}
```

### Scenario 3: Content Delivery

Aggressive caching for static content:

```nginx
location ~* \.(jpg|jpeg|png|gif|webp|svg|css|js|woff2|ttf|eot)$ {
    limit_req zone=static burst=200 nodelay;

    # Long cache times
    expires 1y;
    add_header Cache-Control "public, immutable";

    # Disable ModSecurity for static files (performance)
    modsecurity off;

    # Enable compression
    brotli on;

    root /var/www/html;
}
```

### Scenario 4: Multiple Domains

Create separate configs per domain:

```nginx
# angie/conf.d/site1.com.conf
server {
    listen 443 ssl;
    server_name site1.com;

    acme letsencrypt;
    ssl_certificate     $acme_cert_letsencrypt;
    ssl_certificate_key $acme_cert_key_letsencrypt;

    # Site-specific settings
    root /var/www/site1;

    location / {
        limit_req zone=general burst=20 nodelay;
        try_files $uri $uri/ =404;
    }
}

# angie/conf.d/site2.com.conf
server {
    listen 443 ssl;
    server_name site2.com;

    acme letsencrypt;
    ssl_certificate     $acme_cert_letsencrypt;
    ssl_certificate_key $acme_cert_key_letsencrypt;

    # Different settings for site2
    root /var/www/site2;

    location / {
        limit_req zone=general burst=50 nodelay;
        try_files $uri $uri/ =404;
    }
}
```

## Testing Configuration

### Test Angie Configuration

```bash
docker exec angie angie -t
```

### Reload Angie

```bash
docker exec angie angie -s reload
```

### Test ModSecurity

```bash
# Should be blocked (SQLi)
curl -X GET "https://example.com/?id=1' OR '1'='1"

# Check logs
docker exec angie tail /var/log/angie/error.log | grep ModSecurity
```

### Test Rate Limiting

```bash
# Send rapid requests
for i in {1..50}; do
    curl -w "%{http_code}\n" https://example.com/
done

# Should see 200s followed by 429s
```

### Test Fail2Ban

```bash
# Check status
docker exec fail2ban fail2ban-client status

# Check specific jail
docker exec fail2ban fail2ban-client status angie-modsecurity

# Check banned IPs
docker exec fail2ban fail2ban-client status angie-modsecurity | grep "Banned IP"
```

### Test OAuth2

```bash
# Should redirect to login
curl -L https://example.com/admin

# Check OAuth2-Proxy logs
docker logs oauth2-proxy
```

## Security Hardening

### 1. Whitelist Trusted IPs

```nginx
# In rate-limiting.conf
geo $limit {
    default 1;
    127.0.0.1 0;
    172.18.0.0/16 0;
    203.0.113.50 0;  # Your monitoring service
    203.0.113.51 0;  # Your office IP
}

map $limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=general:10m rate=10r/s;
```

### 2. GeoIP Blocking

```nginx
# Block specific countries
map $geoip2_country_code $blocked_country {
    default 0;
    CN 1;  # China
    RU 1;  # Russia
    # Add as needed
}

server {
    if ($blocked_country = 1) {
        return 403;
    }
    # ... rest of config
}
```

### 3. Block Bad User Agents

```nginx
# In security includes
map $http_user_agent $bad_bot {
    default 0;
    ~*(semrush|ahrefs|mj12bot) 1;
}

server {
    if ($bad_bot = 1) {
        return 403;
    }
    # ... rest of config
}
```

### 4. Strict Security Headers

```nginx
# In security-headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
```

## Maintenance

### Update ModSecurity Rules

```bash
# SSH into container
docker exec -it angie bash

# Update CRS (if mounted from host)
cd /var/lib/angie/modsecurity/coreruleset
git pull

# Test and reload
angie -t && angie -s reload
```

### Update GeoIP Database

```bash
# Download latest GeoIP database
cd geoip/
# Download from MaxMind or use geoipupdate
# Replace GeoLite2-City.mmdb

# Reload Angie
docker exec angie angie -s reload
```

### Rotate Logs

Logs are automatically rotated by Docker, but you can also configure:

```nginx
# In angie.conf
access_log /var/log/angie/access.log json_enriched buffer=64k flush=5s;

# External logrotate (on host)
# /etc/logrotate.d/angie-modsecurity-docker
/path/to/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        docker exec angie angie -s reopen
    endscript
}
```

## Next Steps

- Understand architecture: [Architecture](architecture.md)
- Monitor logs: [Logging System](logging.md)
- Debug issues: [Troubleshooting](troubleshooting.md)
- Review security: [Security Layers](security-layers.md)

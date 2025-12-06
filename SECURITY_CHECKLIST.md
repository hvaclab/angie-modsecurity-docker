# Security Checklist

A comprehensive security checklist for Angie web server deployments.

---

## Already Implemented

- [x] **Fail2Ban** - automatic firewall blocking (5 jails)
- [x] **ModSecurity** - WAF with OWASP CRS 4.18.0 (825+ rules)
- [x] **Log Enrichment** - 70+ enriched fields (GeoIP, User-Agent, Security)
- [x] **SSL/TLS** - Let's Encrypt with auto-renewal (ACME)
- [x] **HTTP/2** - modern protocol
- [x] **HTTP/3 (QUIC)** - protection from some attacks, better performance
- [x] **robots.txt** - search engine control
- [x] **Rate Limiting** - DDoS protection at Angie level
- [x] **Security Headers** - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

---

## Tier 1: Must Have

### 1. Rate Limiting
**Status:** Implemented
**Difficulty:** Low
**Impact:** High

Request rate limiting. DDoS protection before ModSecurity.

**Configuration:**
```nginx
# In http block
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=static:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;

# In location blocks
location / {
    limit_req zone=general burst=20 nodelay;
    try_files $uri $uri/ =404;
}

location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
    limit_req zone=static burst=100 nodelay;
    expires 30d;
}
```

**Testing:**
```bash
./scripts/test-rate-limiting.sh
```

**Monitoring:**
```bash
docker exec angie tail -f /var/log/angie/error.log | grep "limiting requests"
```

---

### 2. Security Headers
**Status:** Implemented
**Difficulty:** Low
**Impact:** High

**Location:** `angie/includes/security/security-headers.conf`

**Headers Set:**
```nginx
# HSTS - 1 year with subdomains and preload
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# Clickjacking protection
add_header X-Frame-Options "DENY" always;

# XSS Protection (legacy)
add_header X-XSS-Protection "1; mode=block" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions Policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

**Verification:**
- Check with https://securityheaders.com/
- Target: A+ rating

---

### 3. SSL/TLS Best Practices
**Status:** Implemented
**Difficulty:** Low
**Impact:** High

**Location:** `angie/includes/security/ssl-params.conf`

**Configuration:**
```nginx
# Modern TLS only
ssl_protocols TLSv1.2 TLSv1.3;

# Strong ciphers
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

# Prefer server ciphers
ssl_prefer_server_ciphers on;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# Session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
```

**Verification:**
- Check with https://www.ssllabs.com/ssltest/
- Target: A+ rating

---

### 4. SSL Certificate Monitoring
**Status:** Template provided
**Difficulty:** Low
**Impact:** High

**Script:** `scripts/check-ssl-expiry.sh`

**Cron Setup:**
```bash
# Check daily at 9 AM
0 9 * * * /path/to/project/scripts/check-ssl-expiry.sh
```

---

## Tier 2: Recommended

### 5. GeoIP Blocking
**Status:** Ready (requires GeoIP databases)
**Difficulty:** Medium
**Impact:** Medium

Block or allow traffic from specific countries.

**Configuration:**
```nginx
# In http block
map $geoip2_data_country_iso_code $allowed_country {
    default 0;
    US 1;
    CA 1;
    GB 1;
    DE 1;
    # Add your allowed countries
}

# In server block
if ($allowed_country = 0) {
    return 403;
}
```

---

### 6. Connection Limits
**Status:** Ready to implement
**Difficulty:** Low
**Impact:** Medium

```nginx
# In http block
limit_conn_zone $binary_remote_addr zone=addr:10m;

# In server block
limit_conn addr 10;  # Max 10 concurrent connections per IP
```

---

### 7. Request Size Limits
**Status:** Implemented
**Difficulty:** Low
**Impact:** Medium

```nginx
client_max_body_size 10m;
client_body_buffer_size 16k;
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
```

---

### 8. Timeout Settings
**Status:** Implemented
**Difficulty:** Low
**Impact:** Medium

```nginx
client_body_timeout 12;
client_header_timeout 12;
keepalive_timeout 15;
send_timeout 10;
```

---

## Tier 3: Advanced

### 9. Honeypot Paths
**Status:** Ready to implement
**Difficulty:** Medium
**Impact:** Medium

Create fake vulnerable paths to detect scanners:

```nginx
location ~ ^/(wp-admin|phpmyadmin|admin\.php|shell\.php) {
    access_log /var/log/angie/honeypot.log;
    return 444;
}
```

---

### 10. Bot Detection
**Status:** Implemented via Fail2Ban
**Difficulty:** Medium
**Impact:** Medium

Bad bots are blocked via `angie-badbots` jail.

---

### 11. ModSecurity Tuning
**Status:** Implemented
**Difficulty:** High
**Impact:** High

**Location:** `modsec/exclusions.conf`

```nginx
# Disable specific rules
SecRuleRemoveById 920100 920200

# Disable for specific URL
SecRule REQUEST_URI "@streq /api/webhook" \
    "id:1001,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

---

### 12. Log Rotation
**Status:** Script provided
**Difficulty:** Low
**Impact:** Medium

**Script:** `scripts/rotate-logs.sh`

**Cron Setup:**
```bash
# Rotate logs daily at 2 AM
0 2 * * * /path/to/project/scripts/rotate-logs.sh
```

---

## Monitoring Recommendations

### Log Aggregation
Ship logs to a centralized system:

```toml
# vector/vector.toml - add Loki sink
[sinks.loki]
type = "loki"
inputs = ["enriched_logs"]
endpoint = "http://loki:3100"
encoding.codec = "json"
labels.job = "angie"
```

### Alerting
Set up alerts for:
- High security scores (threat_level = "high" or "critical")
- Fail2Ban ban events
- ModSecurity blocks
- SSL certificate expiration

### Dashboards
Create dashboards showing:
- Request rate by country
- Top blocked IPs
- Security score distribution
- Response time percentiles

---

## Backup Strategy

### Critical Files to Backup
1. ACME certificates (Docker volume)
2. Configuration files (`angie/`, `modsec/`, `fail2ban/`)
3. Environment file (`.env`)

### Backup Commands
```bash
# Backup ACME certificates
docker run --rm -v project_acme_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/acme-backup.tar.gz -C /data .

# Backup configuration
tar czf config-backup.tar.gz angie/ modsec/ fail2ban/ .env

# Restore ACME certificates
docker run --rm -v project_acme_data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/acme-backup.tar.gz -C /data
```

---

## Security Testing

### Manual Tests
```bash
# Test rate limiting
./scripts/test-rate-limiting.sh

# Test ModSecurity (should be blocked)
curl "https://example.com/?id=1' OR '1'='1"

# Test security headers
curl -I https://example.com | grep -E "(Strict-Transport|Content-Security|X-Frame)"
```

### Online Tools
- https://securityheaders.com/ - Security headers
- https://www.ssllabs.com/ssltest/ - SSL configuration
- https://observatory.mozilla.org/ - Overall security

---

## Quick Reference

| Feature | Status | File |
|---------|--------|------|
| Rate Limiting | Implemented | `includes/security/rate-limiting.conf` |
| Security Headers | Implemented | `includes/security/security-headers.conf` |
| SSL/TLS | Implemented | `includes/security/ssl-params.conf` |
| ModSecurity | Implemented | `modsec/rules.conf` |
| Fail2Ban | Implemented | `fail2ban/jail.d/angie.conf` |
| Log Enrichment | Implemented | `includes/logs/enrichment.conf` |
| GeoIP | Ready | Requires database download |

---

**Template Version:** 1.0.0

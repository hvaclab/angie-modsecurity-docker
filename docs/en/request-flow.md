# Request Flow

This document traces how HTTP requests flow through all security and processing layers in the angie-modsecurity-docker stack.

## Overview

Every request passes through multiple security checkpoints before reaching the backend or serving static content. Understanding this flow is essential for debugging and optimization.

```
Client Request
     ↓
[1. TCP/TLS Connection]
     ↓
[2. Rate Limiting]
     ↓
[3. ModSecurity WAF]
     ↓
[4. OAuth2 Authentication] (optional)
     ↓
[5. Backend/Static Content]
     ↓
[6. Response & Logging]
     ↓
[7. Offline Processing]
```

## Detailed Flow Diagrams

### Legitimate Request Flow

```
┌──────────┐
│  Client  │
└────┬─────┘
     │
     │ HTTPS Request: GET /api/data
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Port 443)                                    │
│                                                     │
│  [1] TCP/TLS Handshake                              │
│      ├─ SSL/TLS 1.3 (or HTTP/3 QUIC)                │
│      ├─ Certificate validation                      │
│      └─ Session establishment                       │
│                                                     │
│  [2] Rate Limiting Check                            │
│      ├─ Extract: $binary_remote_addr (client IP)    │
│      ├─ Check zone: "general" (10 req/s)            │
│      ├─ Decision: 5 req/s → PASS ✓                  │
│      └─ Log to shared memory                        │
│                                                     │
│  [3] Log Enrichment (Level 1)                       │
│      ├─ GeoIP lookup (country, city, lat/lon)       │
│      ├─ User-Agent parsing (browser, OS, device)    │
│      ├─ Security flags (suspicious patterns)        │
│      └─ Performance metrics preparation             │
│                                                     │
│  [4] ModSecurity WAF                                │
│      ├─ Request phase processing                    │
│      │   ├─ Parse HTTP headers                      │
│      │   ├─ Parse request body (if POST/PUT)        │
│      │   ├─ Apply CRS rules (931 rules loaded)      │
│      │   └─ Check: No SQLi, XSS, LFI → PASS ✓       │
│      └─ Anomaly score: 0 (threshold: 5)             │
│                                                     │
│  [5] OAuth2 Authentication (if required)            │
│      ├─ auth_request /oauth2/auth                   │
│      ├─ Subrequest to oauth2-proxy:4180             │
│      │   ├─ Check session cookie                    │
│      │   └─ Return: 202 Accepted ✓                  │
│      ├─ Extract user headers                        │
│      │   ├─ X-Auth-Request-User: john@example.com   │
│      │   └─ X-Auth-Request-Email: john@example.com  │
│      └─ Add headers to backend request              │
│                                                     │
│  [6] Proxy to Backend                               │
│      ├─ Resolve: backend-app:8080 via Docker DNS    │
│      ├─ Add headers:                                │
│      │   ├─ X-Real-IP: 203.0.113.45                 │
│      │   ├─ X-Forwarded-For: 203.0.113.45           │
│      │   ├─ X-User: john@example.com                │
│      │   └─ X-Request-ID: a3f2b1c9...               │
│      └─ Forward request                             │
└─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Backend Application (backend-app:8080)              │
│  ├─ Process request                                 │
│  ├─ Generate response: 200 OK                       │
│  └─ Return: {"status": "success", "data": [...]}    │
└─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Response Phase)                              │
│                                                     │
│  [7] ModSecurity Response Check                     │
│      ├─ Response phase processing                   │
│      ├─ Check response body (if enabled)            │
│      └─ Decision: PASS ✓                            │
│                                                     │
│  [8] Add Security Headers                           │
│      ├─ Strict-Transport-Security                   │
│      ├─ X-Content-Type-Options: nosniff             │
│      ├─ X-Frame-Options: DENY                       │
│      └─ Content-Security-Policy: ...                │
│                                                     │
│  [9] Compression                                    │
│      ├─ Check Accept-Encoding: br, gzip             │
│      ├─ Apply: Brotli compression                   │
│      └─ Size: 15KB → 3KB (80% reduction)            │
│                                                     │
│  [10] Access Logging (Buffered)                     │
│       ├─ Format: json_enriched                      │
│       ├─ Write to buffer (64KB)                     │
│       └─ Log entry:                                 │
│           {                                         │
│             "timestamp": "2025-12-06T15:30:45Z",    │
│             "client_ip": "203.0.113.45",            │
│             "geo_country": "US",                    │
│             "request_method": "GET",                │
│             "request_uri": "/api/data",             │
│             "response_status": "200",               │
│             "perf_request_time": "0.245",           │
│             "security_suspicious_ua": "0",          │
│             ...                                     │
│           }                                         │
└─────────────────────────────────────────────────────┘
     │
     │ HTTPS Response: 200 OK (compressed)
     │
     ▼
┌──────────┐
│  Client  │
└──────────┘

     │
     │ (After response is sent - asynchronous)
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Offline Processing                                  │
│                                                     │
│  [Vector Pipeline]                                  │
│   ├─ Read: /var/log/angie/access.log               │
│   ├─ Parse JSON                                     │
│   ├─ Enrich (Level 2):                              │
│   │   ├─ Calculate security_score = 0               │
│   │   ├─ Set threat_level = "safe"                  │
│   │   └─ Add meta_enriched_by = "vector"            │
│   └─ Write: /var/log/angie/access_enriched.log     │
│                                                     │
│  [Fail2Ban Monitoring]                              │
│   ├─ Tail: /var/log/angie/access.log               │
│   ├─ Apply filters: (no matches)                    │
│   └─ Action: None (legitimate traffic)              │
└─────────────────────────────────────────────────────┘
```

### Attack Request Flow (Blocked by ModSecurity)

```
┌──────────┐
│ Attacker │
└────┬─────┘
     │
     │ HTTPS Request: GET /admin' OR 1=1--
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Port 443)                                    │
│                                                     │
│  [1] TCP/TLS Handshake                              │
│      └─ Connection established ✓                    │
│                                                     │
│  [2] Rate Limiting Check                            │
│      └─ Within limits (first request) → PASS ✓      │
│                                                     │
│  [3] Log Enrichment (Level 1)                       │
│      ├─ GeoIP: CN (China)                           │
│      ├─ User-Agent: sqlmap/1.7.2                    │
│      └─ security_suspicious_ua: "1" ⚠               │
│          security_suspicious_pattern: "1" ⚠         │
│                                                     │
│  [4] ModSecurity WAF                                │
│      ├─ Request phase processing                    │
│      ├─ Parse URI: /admin' OR 1=1--                 │
│      ├─ Rule 942100: SQL Injection detected! 🛑      │
│      │   Pattern: ' OR 1=1--                        │
│      │   Anomaly score: +5                          │
│      ├─ Rule 942190: SQL comment sequence           │
│      │   Pattern: --                                │
│      │   Anomaly score: +5                          │
│      ├─ Total anomaly score: 10 (threshold: 5) 🛑   │
│      │                                              │
│      └─ ACTION: DENY                                │
│          ├─ Log to error.log                        │
│          └─ Return: 403 Forbidden                   │
│                                                     │
│  [5] Error Logging                                  │
│      ├─ error.log entry:                            │
│      │   2025/12/06 15:35:22 [error] ModSecurity:   │
│      │   Access denied with code 403.               │
│      │   Matched "Operator `Rx' with parameter      │
│      │   `(?i:(\s|;|'|")or(\s|;|'|").*?=.*?)`       │
│      │   against variable `ARGS:...'                │
│      │   [client: 203.0.113.100, ...]               │
│      │                                              │
│      └─ access.log entry (403 status):              │
│          {                                          │
│            "timestamp": "2025-12-06T15:35:22Z",     │
│            "client_ip": "203.0.113.100",            │
│            "geo_country": "CN",                     │
│            "ua_string": "sqlmap/1.7.2",             │
│            "request_uri": "/admin' OR 1=1--",       │
│            "response_status": "403",                │
│            "security_suspicious_ua": "1",           │
│            "security_suspicious_pattern": "1",      │
│            ...                                      │
│          }                                          │
└─────────────────────────────────────────────────────┘
     │
     │ HTTPS Response: 403 Forbidden
     │
     ▼
┌──────────┐
│ Attacker │ (Request blocked, backend never reached)
└──────────┘

     │
     │ (Asynchronous processing)
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Offline Processing                                  │
│                                                     │
│  [Vector Pipeline]                                  │
│   ├─ Read: /var/log/angie/access.log               │
│   ├─ Parse JSON                                     │
│   ├─ Enrich (Level 2):                              │
│   │   ├─ security_suspicious_ua = "1" → +5 points   │
│   │   ├─ security_suspicious_pattern = "1" → +7     │
│   │   ├─ Calculate security_score = 12              │
│   │   └─ Set threat_level = "high" 🚨               │
│   └─ Write: /var/log/angie/access_enriched.log     │
│                                                     │
│  [Fail2Ban Monitoring]                              │
│   ├─ Tail: /var/log/angie/error.log                │
│   ├─ Filter: angie-modsecurity                      │
│   ├─ Pattern match: ModSecurity: Access denied      │
│   ├─ Extract IP: 203.0.113.100                      │
│   ├─ Counter: 1st violation                         │
│   └─ Action: Track (threshold: 3 in 5 minutes)      │
│                                                     │
│  (After 2 more ModSecurity blocks within 5 min)    │
│   ├─ Counter: 3 violations → THRESHOLD EXCEEDED     │
│   ├─ Execute: iptables-allports[name=angie-modsec] │
│   ├─ Command: iptables -I f2b-angie-modsec 1        │
│   │           -s 203.0.113.100 -j DROP              │
│   └─ Result: IP banned for 2 hours 🔒               │
└─────────────────────────────────────────────────────┘
```

### DDoS Attack Flow (Blocked by Rate Limiting)

```
┌──────────┐
│ Attacker │
└────┬─────┘
     │
     │ 100 requests/second (burst attack)
     │ GET / GET / GET / ... (100x)
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Port 443)                                    │
│                                                     │
│  [1-10] First 10 requests                           │
│      ├─ Rate limit zone: "general" (10 req/s)       │
│      ├─ Within rate: PASS ✓                         │
│      └─ Process normally                            │
│                                                     │
│  [11-30] Burst requests (11-30)                     │
│      ├─ Rate: 10 req/s + burst: 20                  │
│      ├─ Using burst capacity: PASS ✓                │
│      └─ Process with nodelay                        │
│                                                     │
│  [31-100] Excess requests                           │
│      ├─ Rate limit EXCEEDED 🛑                       │
│      ├─ Burst capacity exhausted                    │
│      ├─ Return: 429 Too Many Requests               │
│      └─ Log to access.log (status: 429)             │
│                                                     │
│  ModSecurity is NOT REACHED (rate limit first)      │
└─────────────────────────────────────────────────────┘
     │
     │ Responses:
     │ - First 30: 200 OK
     │ - Next 70: 429 Too Many Requests
     │
     ▼
┌──────────┐
│ Attacker │
└──────────┘

     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Offline Processing                                  │
│                                                     │
│  [Fail2Ban Monitoring]                              │
│   ├─ Tail: /var/log/angie/access.log               │
│   ├─ Filter: angie-ddos                             │
│   ├─ Pattern: status 429 (not blocking directly)    │
│   │   (alternative: count ANY status)               │
│   ├─ Count requests: 100 in 1 minute                │
│   ├─ Threshold: maxretry=100, findtime=60s          │
│   ├─ Decision: THRESHOLD EXCEEDED                   │
│   │                                                 │
│   └─ Action:                                        │
│       ├─ iptables -I f2b-angie-ddos 1               │
│       │           -s 203.0.113.100 -j DROP          │
│       └─ Ban for 10 minutes 🔒                       │
└─────────────────────────────────────────────────────┘
```

### OAuth2 Protected Resource Flow

```
┌──────────┐
│  Client  │ (No valid session cookie)
└────┬─────┘
     │
     │ HTTPS Request: GET /admin/dashboard
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Port 443)                                    │
│                                                     │
│  [1-3] Normal processing                            │
│      └─ Rate limiting, enrichment: PASS ✓           │
│                                                     │
│  [4] ModSecurity WAF                                │
│      └─ Legitimate request: PASS ✓                  │
│                                                     │
│  [5] OAuth2 Authentication                          │
│      ├─ auth_request /oauth2/auth                   │
│      ├─ Internal subrequest to oauth2-proxy:4180    │
│      │                                              │
│      │   ┌─────────────────────────────────┐        │
│      │   │ OAuth2-Proxy Container          │        │
│      │   │                                 │        │
│      │   │  Check cookie: _oauth2_proxy    │        │
│      │   │  Result: NOT FOUND or EXPIRED   │        │
│      │   │  Return: 401 Unauthorized       │        │
│      │   └─────────────────────────────────┘        │
│      │                                              │
│      ├─ Receive: 401 from oauth2-proxy              │
│      └─ Trigger: error_page 401 = @oauth2_signin    │
│                                                     │
│  [6] Redirect to Login                              │
│      ├─ Location: @oauth2_signin                    │
│      ├─ Set redirect cookie with original URL       │
│      └─ Return: 302 /oauth2/start?rd=https://...    │
└─────────────────────────────────────────────────────┘
     │
     │ 302 Redirect to /oauth2/start
     │
     ▼
┌──────────┐
│  Client  │ (Browser follows redirect)
└────┬─────┘
     │
     │ GET /oauth2/start?rd=https://example.com/admin/dashboard
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie → OAuth2-Proxy                                │
│                                                     │
│  location /oauth2/ {                                │
│      proxy_pass http://oauth2-proxy:4180;           │
│  }                                                  │
└─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ OAuth2-Proxy                                        │
│  ├─ Generate state parameter                        │
│  ├─ Build Keycloak auth URL                         │
│  └─ Return: 302 https://keycloak.../auth            │
└─────────────────────────────────────────────────────┘
     │
     │ 302 Redirect to Keycloak
     │
     ▼
┌──────────┐
│  Client  │ (Keycloak login page)
└────┬─────┘
     │
     │ User enters credentials
     │ POST /auth/realms/myrealm/login
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Keycloak (External)                                 │
│  ├─ Validate credentials                            │
│  ├─ Create session                                  │
│  ├─ Generate authorization code                     │
│  └─ Return: 302 https://example.com/oauth2/callback │
│              ?code=AUTH_CODE&state=...              │
└─────────────────────────────────────────────────────┘
     │
     │ 302 Redirect back with auth code
     │
     ▼
┌──────────┐
│  Client  │
└────┬─────┘
     │
     │ GET /oauth2/callback?code=AUTH_CODE&state=...
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie → OAuth2-Proxy                                │
└─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ OAuth2-Proxy                                        │
│  ├─ Validate state parameter                        │
│  ├─ Exchange code for tokens (call Keycloak)        │
│  ├─ Validate ID token                               │
│  ├─ Extract user info (email, groups)               │
│  ├─ Create session cookie: _oauth2_proxy            │
│  └─ Return: 302 https://example.com/admin/dashboard │
└─────────────────────────────────────────────────────┘
     │
     │ 302 Redirect to original URL (with cookie)
     │
     ▼
┌──────────┐
│  Client  │
└────┬─────┘
     │
     │ GET /admin/dashboard
     │ Cookie: _oauth2_proxy=ENCRYPTED_SESSION
     │
     ▼
┌─────────────────────────────────────────────────────┐
│ Angie (Authenticated Request)                       │
│                                                     │
│  [1-4] Normal processing: PASS ✓                    │
│                                                     │
│  [5] OAuth2 Authentication                          │
│      ├─ auth_request /oauth2/auth                   │
│      ├─ Subrequest with cookie to oauth2-proxy      │
│      │                                              │
│      │   ┌─────────────────────────────────┐        │
│      │   │ OAuth2-Proxy                    │        │
│      │   │  ├─ Decrypt cookie              │        │
│      │   │  ├─ Validate session            │        │
│      │   │  ├─ Check expiry: Valid ✓       │        │
│      │   │  └─ Return: 202 Accepted        │        │
│      │   │     Headers:                    │        │
│      │   │     X-Auth-Request-User: john   │        │
│      │   │     X-Auth-Request-Email: ...   │        │
│      │   └─────────────────────────────────┘        │
│      │                                              │
│      ├─ Receive: 202 Accepted ✓                     │
│      └─ Extract user headers                        │
│                                                     │
│  [6] Proxy to Backend                               │
│      ├─ Add headers:                                │
│      │   ├─ X-User: john@example.com                │
│      │   └─ X-Email: john@example.com               │
│      └─ Forward to backend                          │
└─────────────────────────────────────────────────────┘
     │
     ▼
Backend processes authenticated request
     │
     ▼
Response returned to client (200 OK)
```

## Processing Phases in Detail

### Phase 1: Connection Establishment

**Protocol Negotiation**:
```
Client Hello (TLS 1.3)
  ├─ Supported ciphers
  ├─ SNI: example.com
  └─ ALPN: h3, h2, http/1.1

Server Hello (Angie)
  ├─ Selected: TLS_AES_256_GCM_SHA384
  ├─ Certificate: example.com (Let's Encrypt)
  └─ ALPN selected: h2 (HTTP/2)

Connection established
```

**Key Configuration**:
```nginx
# From ssl-params.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:...;
ssl_prefer_server_ciphers off;

# HTTP/3 support
listen 443 quic reuseport;
add_header Alt-Svc 'h3=":443"; ma=86400';
```

### Phase 2: Rate Limiting

**Process**:
1. Extract key (usually `$binary_remote_addr`)
2. Look up in shared memory zone
3. Check request count against rate
4. Apply burst capacity if defined
5. Decision: PASS or 429

**Zone Definition**:
```nginx
# From rate-limiting.conf
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

# In location
limit_req zone=general burst=20 nodelay;
```

**Memory Layout**:
```
Zone: general (10MB)
├─ 203.0.113.45 → 5 req/s (OK)
├─ 198.51.100.23 → 15 req/s (using burst)
└─ 203.0.113.100 → 31 req/s (BLOCKED)
```

### Phase 3: Log Enrichment (Level 1)

**GeoIP Lookup**:
```nginx
# From enrichment.conf
geoip2 /etc/angie/geoip/GeoLite2-City.mmdb {
    $geoip2_country_code country iso_code;
    $geoip2_city_name city names en;
    # ... more fields
}
```

**User-Agent Analysis**:
```nginx
map $http_user_agent $device_type {
    ~*mobile "mobile";
    ~*bot "bot";
    default "desktop";
}

map $http_user_agent $is_bot {
    ~*(bot|crawler|spider|scraper) 1;
    default 0;
}
```

**Security Flags**:
```nginx
map $http_user_agent $suspicious_ua {
    ~*(sqlmap|nikto|nmap|burp) 1;
    default 0;
}

map $request_uri $suspicious_pattern {
    ~*(union.*select|\.\./) 1;
    default 0;
}
```

### Phase 4: ModSecurity Processing

**Request Phase**:
1. Parse HTTP request (headers + body)
2. Load CRS rules (931+ rules)
3. Execute rule chain
4. Calculate anomaly score
5. Decision: PASS or BLOCK

**Rule Execution**:
```
Rule 920100: Invalid HTTP Request Line → Score: 0
Rule 920280: Missing Host Header → Score: 0
Rule 942100: SQL Injection (OR 1=1) → Score: +5
Rule 942190: SQL Comment Sequence (--) → Score: +5
---
Total Anomaly Score: 10
Threshold: 5
Decision: BLOCK (403)
```

**Configuration**:
```nginx
# From virtual host
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

```
# From modsec/rules.conf
SecRuleEngine On
Include /var/lib/angie/modsecurity/coreruleset/crs-setup.conf
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf
```

### Phase 5: OAuth2 Authentication

**Subrequest Flow**:
```nginx
auth_request /oauth2/auth;

# If 401 returned
error_page 401 = @oauth2_signin;

# Extract user info
auth_request_set $user $upstream_http_x_auth_request_user;
```

**OAuth2-Proxy Decision**:
```
Check cookie: _oauth2_proxy
  ├─ Not present → 401 (redirect to login)
  ├─ Present but expired → 401
  └─ Present and valid → 202
      Headers:
        X-Auth-Request-User: john@example.com
        X-Auth-Request-Email: john@example.com
        X-Auth-Request-Groups: admin,developers
```

### Phase 6: Backend Processing

**Proxy Configuration**:
```nginx
location / {
    proxy_pass http://backend-app:8080;

    # Add client info
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # Add auth info (if authenticated)
    proxy_set_header X-User $user;
    proxy_set_header X-Email $email;

    # Add request tracking
    proxy_set_header X-Request-ID $request_id;
}
```

**Static Files**:
```nginx
location ~* \.(jpg|png|css|js)$ {
    root /var/www/html;
    expires 30d;
    etag on;
}
```

### Phase 7: Response Processing

**ModSecurity Response Phase**:
```
Response received from backend
  ├─ Check response headers
  ├─ Check response body (if enabled)
  └─ Decision: Usually PASS
```

**Security Headers**:
```nginx
# From security-headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
```

**Compression**:
```nginx
# From compression.conf
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json;
```

### Phase 8: Logging

**Access Log Entry**:
```nginx
access_log /var/log/angie/access.log json_enriched buffer=64k flush=5s;
```

**JSON Format**:
```json
{
  "timestamp": "2025-12-06T15:30:45Z",
  "request_id": "a3f2b1c9d8e7f6a5",
  "client_ip": "203.0.113.45",
  "geo_country_code": "US",
  "geo_city": "New York",
  "ua_browser": "chrome",
  "ua_os": "windows",
  "ua_is_bot": "0",
  "request_method": "GET",
  "request_uri": "/api/data",
  "response_status": "200",
  "response_bytes": "3072",
  "perf_request_time": "0.245",
  "security_suspicious_ua": "0",
  "security_suspicious_pattern": "0"
}
```

**Error Log** (ModSecurity blocks):
```
2025/12/06 15:35:22 [error] 42#42: *156 ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Rx' with parameter `(?i:(\s|;|'|")or(\s|;|'|").*?=.*?)` against variable `ARGS:id' (Value: `1' OR '1'='1' ), client: 203.0.113.100, server: example.com, request: "GET /admin?id=1' OR '1'='1 HTTP/2.0", host: "example.com"
```

### Phase 9: Offline Processing

**Vector Pipeline**:
```toml
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]

[transforms.parse_json]
type = "remap"
source = '''
  . = parse_json!(.message)

  # Calculate security score
  score = 0
  if .security_suspicious_ua == "1" { score = score + 5 }
  if .security_suspicious_pattern == "1" { score = score + 7 }
  .security_score = score

  # Classify threat level
  .security_threat_level = if score >= 10 { "high" }
                           else if score >= 5 { "medium" }
                           else { "safe" }
'''
```

**Fail2Ban Monitoring**:
```ini
# angie-modsecurity jail
logpath = /var/log/angie/error.log
filter = angie-modsecurity
maxretry = 3      # 3 ModSecurity blocks
findtime = 300    # within 5 minutes
bantime = 7200    # ban for 2 hours
```

**Ban Process**:
```
1. Log entry detected
2. Regex match: Extract IP
3. Increment counter: 203.0.113.100 → 3 violations
4. Threshold exceeded
5. Execute: iptables -I f2b-angie-modsec -s 203.0.113.100 -j DROP
6. Future requests from IP dropped at firewall level
```

## Performance Characteristics

### Request Latency Breakdown

Typical request (no blocking):
```
TCP/TLS Handshake:        ~50ms  (first request only)
Rate Limiting Check:      ~0.01ms (shared memory lookup)
Log Enrichment:           ~0.1ms  (map lookups, GeoIP)
ModSecurity:              ~2-5ms  (CRS rule processing)
OAuth2 Check:             ~10ms   (if cached, ~100ms if not)
Backend Processing:       ~50ms   (application dependent)
Response Processing:      ~1ms    (headers, compression)
Logging (buffered):       ~0.01ms (writes to buffer)
---
Total: ~113ms (varies)
```

Attack request (blocked by ModSecurity):
```
TCP/TLS Handshake:        ~50ms
Rate Limiting:            ~0.01ms
Log Enrichment:           ~0.1ms
ModSecurity:              ~3ms (blocked early)
Response (403):           ~0.5ms
---
Total: ~53.6ms (backend never reached)
```

Rate limited request:
```
TCP/TLS Handshake:        ~50ms
Rate Limiting:            ~0.01ms (BLOCKED)
Response (429):           ~0.1ms
---
Total: ~50.1ms (ModSecurity never reached)
```

## Next Steps

- Understand security implementation: [Security Layers](security-layers.md)
- Learn logging details: [Logging System](logging.md)
- Configure the stack: [Configuration Guide](configuration.md)
- Debug issues: [Troubleshooting](troubleshooting.md)

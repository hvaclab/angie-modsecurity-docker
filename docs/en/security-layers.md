# Security Layers

This document describes the defense-in-depth security strategy implemented in angie-modsecurity-docker and how each layer interacts with the others.

## Overview

Security in angie-modsecurity-docker is implemented through multiple overlapping layers. Each layer serves a specific purpose and catches different types of threats. When one layer is bypassed, others provide backup protection.

```
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Authentication (OAuth2-Proxy)                  │
│ Purpose: Identity & Authorization                       │
│ Protects: Sensitive resources                           │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Layer 3: IP Banning (Fail2Ban)                          │
│ Purpose: Pattern-based blocking                         │
│ Protects: Against persistent attackers                  │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Layer 2: WAF (ModSecurity + CRS)                        │
│ Purpose: Application-level attack detection             │
│ Protects: Against SQLi, XSS, RCE, etc.                  │
└─────────────────────────────────────────────────────────┘
                          ↑
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Rate Limiting (Angie)                          │
│ Purpose: Resource protection                            │
│ Protects: Against DDoS, brute force                     │
└─────────────────────────────────────────────────────────┘
                          ↑
                    Internet Traffic
```

## Layer 1: Rate Limiting (Angie)

### Purpose

Protect server resources from exhaustion by limiting request rates before expensive processing occurs.

### When It Acts

**First line of defense** - Evaluated before ModSecurity, before authentication, before everything.

### Configuration

```nginx
# From includes/security/rate-limiting.conf

# Zone definitions
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=static:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=forms:10m rate=2r/s;

# Global settings
limit_req_status 429;
limit_req_log_level warn;
```

### Application

```nginx
# In virtual host
location / {
    limit_req zone=general burst=20 nodelay;
    # ... rest of config
}

location ~* \.(jpg|jpeg|png|css|js)$ {
    limit_req zone=static burst=100 nodelay;
    # ... rest of config
}
```

### What It Catches

1. **DDoS Attacks**: 100+ requests/second from single IP
2. **Brute Force**: Rapid login attempts
3. **Resource Exhaustion**: Too many concurrent connections
4. **Scraping**: Automated content extraction

### How It Works

```
Request from 203.0.113.45
    ↓
Extract key: $binary_remote_addr = 203.0.113.45
    ↓
Lookup in shared memory zone "general"
    ↓
Check: Current rate = 8 req/s
    ↓
Limit: 10 req/s + burst 20
    ↓
Decision: 8 < 10 → PASS ✓
    ↓
Increment counter
    ↓
Continue to next layer
```

**When limit exceeded**:
```
Request from 203.0.113.45 (request #35 in 1 second)
    ↓
Current rate: 35 req/s
    ↓
Limit: 10 req/s + burst 20 = max 30
    ↓
Decision: 35 > 30 → BLOCK 🛑
    ↓
Return: 429 Too Many Requests
    ↓
Log to access.log with status 429
    ↓
ModSecurity NEVER REACHED (saves CPU)
```

### Integration with Other Layers

**With ModSecurity**:
- Rate limiting runs FIRST (cheaper operation)
- Prevents DDoS from overwhelming ModSecurity rules
- ModSecurity only sees requests within rate limit

**With Fail2Ban**:
- Fail2Ban can track 429 responses (optional)
- Persistent rate limit violations → IP ban
- Two-tier defense: rate limit + ban

**Configuration Example**:
```ini
# fail2ban/jail.d/angie.conf
[angie-ddos]
enabled = true
filter = angie-ddos
logpath = /var/log/angie/access.log
maxretry = 100  # 100 requests
findtime = 60   # in 60 seconds
bantime = 600   # ban for 10 minutes
```

### Tuning Guidelines

**For high-traffic sites**:
```nginx
limit_req_zone $binary_remote_addr zone=general:10m rate=50r/s;
limit_req zone=general burst=100 nodelay;
```

**For API endpoints**:
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
limit_req zone=api burst=10 nodelay;
```

**For login forms**:
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req zone=login burst=3 nodelay;
```

### Whitelist Implementation

```nginx
# Create whitelist map
geo $limit {
    default 1;
    127.0.0.1 0;           # localhost
    172.18.0.0/16 0;       # Docker network
    203.0.113.50 0;        # Trusted monitoring service
}

map $limit $limit_key {
    0 "";                  # Empty = bypass
    1 $binary_remote_addr; # Normal = apply limit
}

# Use in zone
limit_req_zone $limit_key zone=general:10m rate=10r/s;
```

## Layer 2: Web Application Firewall (ModSecurity)

### Purpose

Detect and block application-level attacks by analyzing HTTP requests and responses against security rules.

### When It Acts

**After rate limiting**, but before backend processing. Embedded in Angie as a module.

### Configuration

```nginx
# From angie.conf
load_module modules/ngx_http_modsecurity_module.so;

# From virtual host
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

```
# From modsec/rules.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# OWASP CRS
Include /var/lib/angie/modsecurity/coreruleset/crs-setup.conf
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf

# Custom exclusions
Include /etc/angie/modsecurity/exclusions.conf
```

### What It Catches

1. **SQL Injection (SQLi)**: `' OR 1=1--`, `UNION SELECT`, etc.
2. **Cross-Site Scripting (XSS)**: `<script>`, `onerror=`, `javascript:`
3. **Remote Code Execution (RCE)**: Shell commands, eval(), etc.
4. **Local File Inclusion (LFI)**: `../../etc/passwd`
5. **Command Injection**: `; rm -rf /`, `| cat /etc/passwd`
6. **Protocol Violations**: Malformed HTTP, missing headers
7. **Bad Bots**: Known malicious user agents

### How It Works

**Request Phase**:
```
Request: GET /admin?id=1' OR '1'='1

ModSecurity Processing:
    ↓
Parse request:
  - Method: GET
  - URI: /admin
  - Query string: id=1' OR '1'='1
  - Headers: {...}
    ↓
Apply rule chain (931+ rules):
    ↓
Rule 920100: Invalid HTTP Request → Score: 0 (OK)
Rule 920280: Missing Host header → Score: 0 (OK)
Rule 942100: SQL Injection detected → Score: +5 ⚠
  Pattern matched: ' OR '.*?'
  Variable: ARGS:id
  Value: 1' OR '1'='1
    ↓
Rule 942190: SQL comment sequence → Score: +5 ⚠
  Pattern matched: --
    ↓
Total Anomaly Score: 10
Inbound Threshold: 5
    ↓
Decision: BLOCK 🛑
    ↓
Log to error.log:
  ModSecurity: Access denied with code 403
  [client: 203.0.113.100]
    ↓
Return: 403 Forbidden
```

**Legitimate Request**:
```
Request: GET /api/users?page=2

ModSecurity Processing:
    ↓
Parse request:
  - Method: GET
  - URI: /api/users
  - Query string: page=2
    ↓
Apply rule chain:
    ↓
All rules: No matches
    ↓
Total Anomaly Score: 0
Threshold: 5
    ↓
Decision: PASS ✓
    ↓
Continue to backend
```

### Integration with Other Layers

**With Rate Limiting**:
- Rate limiting runs first (protects ModSecurity from overload)
- ModSecurity sees only rate-limited traffic
- Prevents CPU exhaustion from rule processing

**With Fail2Ban**:
- ModSecurity logs blocks to error.log
- Fail2Ban reads error.log for ModSecurity violations
- Multiple violations → IP ban

**Example Fail2Ban Filter**:
```
# fail2ban/filter.d/angie-modsecurity.conf
[Definition]
failregex = ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[error\].*ModSecurity: Access denied.*client: <HOST>,
```

**Jail Configuration**:
```ini
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3      # 3 ModSecurity blocks
findtime = 300    # within 5 minutes
bantime = 7200    # ban for 2 hours
```

**Attack Scenario**:
```
Attacker tries SQL injection 4 times:

Request 1: ' OR 1=1--
  → ModSecurity: BLOCK (403)
  → Fail2Ban counter: 1

Request 2: UNION SELECT
  → ModSecurity: BLOCK (403)
  → Fail2Ban counter: 2

Request 3: admin' --
  → ModSecurity: BLOCK (403)
  → Fail2Ban counter: 3 → THRESHOLD EXCEEDED
  → Fail2Ban: BAN IP for 2 hours

Request 4: (any request)
  → iptables: DROP (packet never reaches Angie)
```

### Anomaly Scoring

ModSecurity uses anomaly scoring mode (recommended):

```
Severity Levels:
  CRITICAL: +5 points (SQLi, RCE)
  ERROR:    +4 points (LFI, XSS)
  WARNING:  +3 points (Protocol violations)
  NOTICE:   +2 points (Suspicious patterns)

Thresholds:
  Inbound:  5 (blocking threshold)
  Outbound: 4 (response inspection)

Example:
  Rule 942100 (SQLi): +5 → Total: 5 → BLOCK
  Rule 941100 (XSS): +4 + Rule 941110: +4 → Total: 8 → BLOCK
```

### Custom Exclusions

Sometimes legitimate requests trigger false positives:

```
# modsec/exclusions.conf

# Disable rule 920273 for specific admin path
SecRuleRemoveById 920273
SecRule REQUEST_URI "@beginsWith /admin/upload" \
    "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=920273"

# Allow larger POST body for API
SecRule REQUEST_URI "@beginsWith /api/v1/upload" \
    "id:1001,phase:1,pass,nolog,ctl:requestBodyLimit=10485760"

# Skip WAF for specific trusted endpoint
SecRule REQUEST_URI "@streq /health" \
    "id:1002,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

## Layer 3: IP Banning (Fail2Ban)

### Purpose

Automatically ban IP addresses that exhibit malicious patterns by analyzing logs and applying firewall rules.

### When It Acts

**After requests are logged** - Offline processing that affects future requests.

### Architecture

```
Angie writes logs
    ↓
/var/log/angie/access.log (all requests)
/var/log/angie/error.log  (ModSecurity blocks)
    ↓
Fail2Ban tails logs (real-time)
    ↓
Apply regex filters
    ↓
Extract IP addresses
    ↓
Count violations per IP
    ↓
If threshold exceeded:
  └─> iptables ban
```

### Configuration

```ini
# fail2ban/jail.d/angie.conf

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16

# Jail 1: Bad HTTP requests (400 errors)
[angie-bad-request]
enabled = true
filter = angie-bad-request
logpath = /var/log/angie/access.log
maxretry = 5
findtime = 300
bantime = 3600
action = iptables-allports[name=angie-bad-request]

# Jail 2: ModSecurity violations
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3
findtime = 300
bantime = 7200
action = iptables-allports[name=angie-modsec]

# Jail 3: Scanner detection (404 scanning)
[angie-scan]
enabled = true
filter = angie-scan
logpath = /var/log/angie/access.log
maxretry = 10
findtime = 600
bantime = 86400
action = iptables-allports[name=angie-scan]

# Jail 4: DDoS protection
[angie-ddos]
enabled = true
filter = angie-ddos
logpath = /var/log/angie/access.log
maxretry = 100
findtime = 60
bantime = 600
action = iptables-allports[name=angie-ddos]
```

### Filter Definitions

```
# fail2ban/filter.d/angie-modsecurity.conf
[Definition]
failregex = ModSecurity: Access denied.*client: <HOST>,

# fail2ban/filter.d/angie-bad-request.conf
[Definition]
failregex = "client_ip":"<HOST>".*"response_status":"400"

# fail2ban/filter.d/angie-scan.conf
[Definition]
failregex = "client_ip":"<HOST>".*"response_status":"404".*"request_uri":".*\.(php|asp|aspx|cgi|env|git)"
```

### How It Works

**Example: Attacker scanning for vulnerabilities**

```
Time 15:00:00 - GET /admin.php → 404
  Fail2Ban: angie-scan counter[203.0.113.100] = 1

Time 15:00:05 - GET /wp-admin/ → 404
  Fail2Ban: angie-scan counter[203.0.113.100] = 2

Time 15:00:10 - GET /.env → 404
  Fail2Ban: angie-scan counter[203.0.113.100] = 3

... (continues)

Time 15:05:00 - GET /config.php → 404
  Fail2Ban: angie-scan counter[203.0.113.100] = 10
  Threshold: maxretry=10, findtime=600s (10 min)
  Decision: BAN 🔒

  Execute:
    iptables -I f2b-angie-scan 1 \
             -s 203.0.113.100 \
             -j DROP

  Ban duration: 86400s (24 hours)

Time 15:05:01 - Any request from 203.0.113.100
  iptables: DROP (packet dropped before reaching Angie)
```

### Integration with Other Layers

**With ModSecurity**:
```
Attacker → SQL Injection Attempt
    ↓
Angie (Rate Limit): PASS (first attempt)
    ↓
ModSecurity: BLOCK → 403
    ↓
Log to error.log: "ModSecurity: Access denied, client: 203.0.113.100"
    ↓
Fail2Ban reads error.log
    ↓
Pattern match: Extract IP 203.0.113.100
    ↓
Counter: 1st violation (threshold: 3)
    ↓
(After 2 more attempts)
    ↓
Counter: 3rd violation → BAN
    ↓
iptables rule: DROP all from 203.0.113.100
    ↓
Next attack attempt:
  → Dropped at firewall (never reaches Angie or ModSecurity)
```

**With Rate Limiting**:
```
Attacker → DDoS (200 req/s)
    ↓
Angie Rate Limit: First 30 requests PASS, rest get 429
    ↓
Logs: 170 × status 429 in 1 minute
    ↓
Fail2Ban (angie-ddos jail):
  maxretry=100, findtime=60
  Decision: BAN
    ↓
All future requests: iptables DROP
```

### Unban Process

**Automatic**:
```
Ban time expires (e.g., after 2 hours)
    ↓
Fail2Ban removes iptables rule
    ↓
IP can access again (clean slate)
```

**Manual**:
```bash
# List banned IPs
docker exec fail2ban fail2ban-client status angie-modsecurity

# Unban specific IP
docker exec fail2ban fail2ban-client set angie-modsecurity unbanip 203.0.113.100

# Unban all
docker exec fail2ban fail2ban-client reload
```

### Network Architecture

**Why host network mode?**

```yaml
# compose.yml
fail2ban:
  network_mode: "host"  # Required!
```

Fail2Ban needs to modify host iptables:
```
Container Network (bridge):
  ├─ Container has own network namespace
  ├─ iptables rules only affect container
  └─ Cannot block host-level traffic ❌

Host Network:
  ├─ Container shares host network namespace
  ├─ iptables rules affect host firewall
  └─ Can block traffic before Docker routing ✓
```

## Layer 4: Authentication (OAuth2-Proxy)

### Purpose

Provide authentication and authorization for protected resources using Keycloak (or other OIDC providers).

### When It Acts

**After rate limiting and ModSecurity**, but before backend access. Only for protected paths.

### Architecture

```
Client → Angie
    ↓
Protected resource: /admin/dashboard
    ↓
auth_request /oauth2/auth
    ↓
Subrequest to OAuth2-Proxy:4180
    ↓
OAuth2-Proxy checks session cookie
    ├─ Valid → 202 Accepted → Continue to backend
    └─ Invalid → 401 → Redirect to Keycloak login
```

### Configuration

```nginx
# From includes/auth/keycloak-auth.conf

# Internal auth endpoint
location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180/oauth2/auth;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # ... more headers
}

# OAuth2 endpoints (callback, sign-in/out)
location /oauth2/ {
    proxy_pass http://oauth2-proxy:4180;
    # ... proxy settings
}

# Error handler for unauthorized
location @oauth2_signin {
    internal;
    return 302 /oauth2/start?rd=$scheme://$host$request_uri;
}
```

```nginx
# Usage in protected location
location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    # Extract user info
    auth_request_set $user $upstream_http_x_auth_request_user;
    auth_request_set $email $upstream_http_x_auth_request_email;

    # Pass to backend
    proxy_set_header X-User $user;
    proxy_set_header X-Email $email;
    proxy_pass http://backend:8080;
}
```

### OAuth2-Proxy Configuration

```yaml
# From compose.yml
environment:
  - OAUTH2_PROXY_PROVIDER=keycloak-oidc
  - OAUTH2_PROXY_OIDC_ISSUER_URL=${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}
  - OAUTH2_PROXY_CLIENT_ID=${KEYCLOAK_CLIENT_ID}
  - OAUTH2_PROXY_CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}
  - OAUTH2_PROXY_COOKIE_SECRET=${KEYCLOAK_COOKIE_SECRET}
  - OAUTH2_PROXY_REVERSE_PROXY=true
  - OAUTH2_PROXY_SET_XAUTHREQUEST=true
```

### How It Works

**Authentication Flow**:

```
1. User requests: GET /admin/dashboard
     ↓
2. Angie: auth_request /oauth2/auth (internal subrequest)
     ↓
3. OAuth2-Proxy: Check cookie _oauth2_proxy
     ├─ Cookie present and valid:
     │    └→ Return 202 + user headers
     │       X-Auth-Request-User: john@example.com
     │       X-Auth-Request-Email: john@example.com
     │       X-Auth-Request-Groups: admin,developer
     └─ Cookie missing or expired:
          └→ Return 401 Unauthorized
     ↓
4. If 202: Continue to backend with user headers
   If 401: error_page 401 = @oauth2_signin
     ↓
5. @oauth2_signin: Redirect to /oauth2/start?rd=...
     ↓
6. OAuth2-Proxy: Redirect to Keycloak login
     ↓
7. User logs in to Keycloak
     ↓
8. Keycloak: Redirect back with auth code
     ↓
9. OAuth2-Proxy: Exchange code for tokens
     ↓
10. OAuth2-Proxy: Set cookie, redirect to original URL
     ↓
11. User requests /admin/dashboard again (now with cookie)
     ↓
12. Auth succeeds → Access granted ✓
```

### Integration with Other Layers

**With ModSecurity**:
```
Request to /admin (protected)
    ↓
Rate Limiting: PASS
    ↓
ModSecurity: PASS (legitimate request)
    ↓
OAuth2 Auth: Check authentication
    ├─ Not authenticated → Redirect to login
    └─ Authenticated → Continue
```

ModSecurity analyzes OAuth2 requests too:
- Login forms
- Callback URLs
- Token exchanges

**With Fail2Ban**:
```
Attacker trying to brute force login:

Attempt 1-5: Failed logins
  → OAuth2-Proxy logs failed attempts
  → Angie logs: 401 Unauthorized

(Optional) Fail2Ban jail for auth failures:
[oauth2-auth-failure]
filter = oauth2-failed-login
maxretry = 5
findtime = 300
bantime = 3600
```

### Role-Based Access

OAuth2-Proxy extracts groups/roles from Keycloak:

```nginx
# Advanced: Check for specific role
location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    auth_request_set $groups $upstream_http_x_auth_request_groups;

    # Pass groups to backend
    proxy_set_header X-Groups $groups;

    # Backend checks if "admin" in groups
    proxy_pass http://backend:8080;
}
```

Backend application:
```python
# Example backend logic
groups = request.headers.get('X-Groups', '').split(',')

if 'admin' not in groups:
    return 403, "Forbidden: Admin access required"
```

## Layer Interaction Summary

### Defense in Depth Scenarios

**Scenario 1: DDoS Attack**

```
Layer 1 (Rate Limiting): ✓ BLOCKS most traffic (429)
Layer 2 (ModSecurity): Not reached (saved CPU)
Layer 3 (Fail2Ban): Bans IP after threshold
Layer 4 (OAuth2): Not reached
```

**Scenario 2: SQL Injection**

```
Layer 1 (Rate Limiting): ✓ PASS (within limit)
Layer 2 (ModSecurity): ✓ BLOCKS (detects SQLi, returns 403)
Layer 3 (Fail2Ban): Tracks violations, bans after 3 attempts
Layer 4 (OAuth2): Not reached
```

**Scenario 3: Unauthorized Access**

```
Layer 1 (Rate Limiting): ✓ PASS
Layer 2 (ModSecurity): ✓ PASS (legitimate request structure)
Layer 3 (Fail2Ban): Not triggered
Layer 4 (OAuth2): ✓ BLOCKS (no valid session, redirects to login)
```

**Scenario 4: Legitimate User**

```
Layer 1 (Rate Limiting): ✓ PASS (normal rate)
Layer 2 (ModSecurity): ✓ PASS (no malicious patterns)
Layer 3 (Fail2Ban): Not triggered
Layer 4 (OAuth2): ✓ PASS (valid session) → Backend
```

### Processing Order

```
Internet Request
    ↓
[0] iptables (if IP banned by Fail2Ban) → DROP
    ↓
[1] Angie receives request
    ↓
[2] Rate Limiting → 429 or PASS
    ↓
[3] ModSecurity WAF → 403 or PASS
    ↓
[4] OAuth2 (if required) → 401/redirect or PASS
    ↓
[5] Backend/Static content
    ↓
[6] ModSecurity response phase
    ↓
[7] Response sent
    ↓
[8] Logging (asynchronous)
    ↓
[9] Fail2Ban reads logs (offline)
    ↓
[10] Fail2Ban updates iptables (if needed)
```

### Complementary Protection

Each layer protects others:

**Rate Limiting protects**:
- ModSecurity from CPU exhaustion
- Backend from connection exhaustion
- Logging system from disk exhaustion

**ModSecurity protects**:
- Backend from application attacks
- Database from SQL injection
- Users from XSS attacks

**Fail2Ban protects**:
- All layers from persistent attackers
- System resources from wasted processing
- Reduces log noise

**OAuth2 protects**:
- Sensitive resources from unauthorized access
- User data from exposure
- Admin panels from anonymous access

## Security Best Practices

### Tuning Recommendations

1. **Start conservative, then relax**
   - Begin with strict limits
   - Monitor false positives
   - Gradually adjust thresholds

2. **Layer-specific tuning**
   - Rate limits: Based on legitimate traffic patterns
   - ModSecurity: Use paranoia level 1 initially
   - Fail2Ban: Adjust ban times based on attack frequency
   - OAuth2: Set appropriate session timeouts

3. **Whitelist trusted sources**
   - Monitoring services
   - CI/CD pipelines
   - Partner APIs
   - CDN origins

4. **Regular updates**
   - ModSecurity CRS rules
   - GeoIP databases
   - Fail2Ban filters

### Monitoring

Track metrics at each layer:

```bash
# Rate limiting
grep "limiting requests" /var/log/angie/error.log

# ModSecurity
grep "ModSecurity: Access denied" /var/log/angie/error.log | wc -l

# Fail2Ban
docker exec fail2ban fail2ban-client status

# OAuth2
docker logs oauth2-proxy | grep "401"
```

## Next Steps

- Configure security: [Configuration Guide](configuration.md)
- Understand request flow: [Request Flow](request-flow.md)
- Monitor logs: [Logging System](logging.md)
- Debug issues: [Troubleshooting](troubleshooting.md)

# System Architecture

This document describes how the components in angie-modsecurity-docker are connected and how they communicate with each other.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Docker Host                              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    angie_network (bridge)                   │ │
│  │                                                              │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │ │
│  │  │    Angie     │───▶│ OAuth2-Proxy │    │   Vector     │ │ │
│  │  │  Port 80/443 │    │  Port 4180   │    │              │ │ │
│  │  │              │    │              │    │              │ │ │
│  │  │ + ModSecurity│    │ (Keycloak)   │    │ (Enrichment) │ │ │
│  │  └──────┬───────┘    └──────────────┘    └──────┬───────┘ │ │
│  │         │                                        │         │ │
│  └─────────┼────────────────────────────────────────┼─────────┘ │
│            │                                        │           │
│            │         ┌──────────────────┐           │           │
│            │         │ Logs Directory   │           │           │
│            └────────▶│ /var/log/angie/  │◀──────────┘           │
│                      │                  │                       │
│                      │ • access.log     │                       │
│                      │ • error.log      │                       │
│                      │ • access_enri... │                       │
│                      └────────┬─────────┘                       │
│                               │                                 │
│                               │ (read-only)                     │
│                               │                                 │
│                      ┌────────▼─────────┐                       │
│                      │    Fail2Ban      │                       │
│                      │  (network: host) │                       │
│                      │                  │                       │
│                      │  • Reads logs    │                       │
│                      │  • Bans IPs      │                       │
│                      └──────────────────┘                       │
│                               │                                 │
└───────────────────────────────┼─────────────────────────────────┘
                                │
                                ▼
                        Host iptables
                        (IP blocking)
```

## Component Responsibilities

### 1. Angie (Web Server + ModSecurity)

**Container**: `angie`
**Network**: `angie_network` + exposed ports 80, 443
**Image**: Custom build with ModSecurity module

**Primary Functions**:
- HTTP/HTTPS/HTTP3 request handling
- SSL/TLS termination
- Rate limiting (before ModSecurity)
- Reverse proxy to backend services
- ModSecurity WAF execution
- Log enrichment (GeoIP, User-Agent analysis)
- OAuth2 authentication requests

**Key Configuration**:
```yaml
# From compose.yml
ports:
  - "80:80"
  - "443:443/tcp"
  - "443:443/udp"  # HTTP/3 (QUIC)

volumes:
  - ./angie/angie.conf:/etc/angie/angie.conf:ro
  - ./angie/includes:/etc/angie/includes:ro
  - ./logs:/var/log/angie
  - ./modsec:/etc/angie/modsecurity:ro
```

**Integration Points**:
- Writes logs to shared `/var/log/angie` directory
- Proxies auth requests to OAuth2-Proxy container
- Embeds ModSecurity as a dynamic module
- Uses shared Docker network for container resolution

See [Request Flow](request-flow.md) for request processing details.

### 2. ModSecurity (Web Application Firewall)

**Location**: Loaded as Angie module
**Not a separate container**

**Primary Functions**:
- Analyze HTTP requests and responses
- Apply OWASP Core Rule Set (CRS)
- Block malicious patterns (SQLi, XSS, etc.)
- Write blocking events to error log

**Key Configuration**:
```nginx
# From angie.conf
load_module modules/ngx_http_modsecurity_module.so;

# From virtual host config
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

**Integration Points**:
- Embedded in Angie process (not separate)
- Logs violations to `/var/log/angie/error.log`
- Blocks happen before response is sent
- Works with Angie's rate limiting

See [Security Layers](security-layers.md#modsecurity-layer) for WAF details.

### 3. OAuth2-Proxy (Authentication)

**Container**: `oauth2-proxy`
**Network**: `angie_network` (internal only)
**Port**: 4180 (not exposed)

**Primary Functions**:
- OIDC authentication with Keycloak
- Session cookie management
- User information extraction
- Auth subrequest handling

**Key Configuration**:
```yaml
# From compose.yml
environment:
  - OAUTH2_PROXY_PROVIDER=keycloak-oidc
  - OAUTH2_PROXY_CLIENT_ID=${KEYCLOAK_CLIENT_ID}
  - OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180
  - OAUTH2_PROXY_REVERSE_PROXY=true
```

**Integration Points**:
- Receives auth subrequests from Angie
- Returns user headers (X-Auth-Request-User, X-Auth-Request-Email)
- Handles OAuth2 callbacks and redirects
- Not directly accessible from internet

**Angie Integration**:
```nginx
# From keycloak-auth.conf
location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180/oauth2/auth;
    # ... proxy settings
}

# In protected locations
auth_request /oauth2/auth;
error_page 401 = @oauth2_signin;
```

See [Configuration Guide](configuration.md#oauth2-authentication) for setup details.

### 4. Vector (Log Enrichment)

**Container**: `vector`
**Network**: `angie_network`
**No exposed ports**

**Primary Functions**:
- Read Angie's JSON logs
- Parse and enrich log data
- Calculate security scores
- Write enhanced logs

**Key Configuration**:
```toml
# From vector.toml
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]

[transforms.parse_json]
type = "remap"
# Calculates security_score
# Adds threat_level classification

[sinks.enriched_logs]
type = "file"
path = "/var/log/angie/access_enriched.log"
```

**Integration Points**:
- Reads from shared logs directory
- Writes back to same directory
- Independent processing (doesn't block requests)
- Adds intelligence layer for analysis

See [Logging System](logging.md#vector-enrichment) for pipeline details.

### 5. Fail2Ban (IP Banning)

**Container**: `fail2ban`
**Network**: `host` (must access host iptables)
**Privileged**: Yes (needs iptables access)

**Primary Functions**:
- Monitor Angie logs for patterns
- Detect repeated violations
- Ban IPs using iptables
- Automatic unban after timeout

**Key Configuration**:
```yaml
# From compose.yml
network_mode: "host"  # Required for iptables
volumes:
  - ./logs:/var/log/angie:ro
  - ./fail2ban:/data
```

**Jail Configuration**:
```ini
# From jail.d/angie.conf
[angie-modsecurity]
enabled = true
filter = angie-modsecurity
logpath = /var/log/angie/error.log
maxretry = 3
findtime = 300
bantime = 7200
action = iptables-allports[name=angie-modsec]
```

**Integration Points**:
- Reads logs via read-only mount
- Uses host network to modify iptables
- Multiple filters for different attack types
- Independent from request processing

See [Security Layers](security-layers.md#fail2ban-layer) for banning logic.

## Data Flow Patterns

### Shared Logs Directory

The `/var/log/angie` directory is the central communication hub:

```
/var/log/angie/
├── access.log              (Written by: Angie)
│                          (Read by: Fail2Ban, Vector)
├── error.log               (Written by: Angie + ModSecurity)
│                          (Read by: Fail2Ban)
└── access_enriched.log     (Written by: Vector)
```

**Mount Points**:
```yaml
# Angie: Read-write
- ./logs:/var/log/angie

# Fail2Ban: Read-only
- ./logs:/var/log/angie:ro

# Vector: Read-write
- ./logs:/var/log/angie
```

### Network Architecture

**Bridge Network (`angie_network`)**:
- Angie can reach OAuth2-Proxy by container name
- Vector can access logs through shared mount
- Internal DNS resolution via Docker (127.0.0.11)

**Host Network (Fail2Ban)**:
- Required to modify host iptables rules
- Can read logs via volume mount
- Bans affect all incoming traffic

**Port Mapping**:
```yaml
Angie:
  80:80    → HTTP (redirects to HTTPS)
  443:443/tcp → HTTPS + HTTP/2
  443:443/udp → HTTP/3 (QUIC)

OAuth2-Proxy:
  4180 → Internal only (not exposed)

Fail2Ban:
  Host network → Direct iptables access
```

## Configuration File Structure

```
angie-modsecurity-docker/
├── compose.yml                    # Container orchestration
├── angie/
│   ├── angie.conf                 # Main config + module loading
│   ├── includes/
│   │   ├── security/
│   │   │   ├── rate-limiting.conf # Zone definitions
│   │   │   ├── ssl-params.conf    # TLS configuration
│   │   │   └── headers-advanced.conf
│   │   ├── logs/
│   │   │   ├── enrichment.conf    # GeoIP, User-Agent maps
│   │   │   └── log-formats.conf   # JSON format definition
│   │   ├── auth/
│   │   │   └── keycloak-auth.conf # OAuth2-Proxy integration
│   │   └── performance/
│   │       └── compression.conf   # Brotli, Zstd, Gzip
│   └── conf.d/
│       └── *.conf                 # Virtual host configs
├── modsec/
│   ├── rules.conf                 # ModSecurity + CRS
│   └── exclusions.conf            # Custom exclusions
├── fail2ban/
│   ├── jail.d/
│   │   └── angie.conf             # Jail definitions
│   └── filter.d/
│       ├── angie-modsecurity.conf # ModSecurity filter
│       ├── angie-bad-request.conf # HTTP 400 filter
│       └── angie-scan.conf        # Scanner detection
└── vector/
    └── vector.toml                # Log pipeline config
```

## Module Loading Order

Understanding the order is crucial for troubleshooting:

```nginx
# 1. Load dynamic modules FIRST
load_module modules/ngx_http_modsecurity_module.so;
load_module modules/ngx_http_geoip2_module.so;
load_module modules/ngx_http_headers_more_filter_module.so;

# 2. Define enrichment (maps, geoip)
include /etc/angie/includes/logs/enrichment.conf;

# 3. Define rate limiting zones
include /etc/angie/includes/security/rate-limiting.conf;

# 4. Define log formats
include /etc/angie/includes/logs/log-formats.conf;

# 5. Enable access logging
access_log /var/log/angie/access.log json_enriched;

# 6. Load virtual hosts
include /etc/angie/conf.d/*.conf;
```

Each virtual host then applies these in order:
1. Rate limiting (before ModSecurity)
2. ModSecurity WAF
3. OAuth2 authentication (if enabled)
4. Proxy pass or static content

## Container Communication

### Angie → OAuth2-Proxy

```nginx
# Angie configuration
resolver 127.0.0.11 valid=10s;  # Docker DNS

location = /oauth2/auth {
    internal;
    proxy_pass http://oauth2-proxy:4180/oauth2/auth;
    # Container name resolves via Docker DNS
}
```

**Process**:
1. Angie receives request for protected resource
2. Triggers `auth_request /oauth2/auth`
3. Makes subrequest to `oauth2-proxy:4180`
4. OAuth2-Proxy checks cookie/redirects to Keycloak
5. Returns 202 (authenticated) or 401 (denied)
6. Angie proceeds or redirects based on response

### Angie → Logs → Fail2Ban

```
[Request] → Angie → access.log (JSON)
                    error.log (ModSec violations)
                         ↓
                    Fail2Ban reads logs
                         ↓
                    Pattern matching
                         ↓
                    iptables ban
```

**Process**:
1. Angie writes log entry immediately
2. Fail2Ban tails logs in real-time
3. Regex filter extracts IP addresses
4. Counter increments for IP
5. If threshold exceeded: ban via iptables

### Angie → Logs → Vector

```
[Request] → Angie → access.log (JSON with basic enrichment)
                         ↓
                    Vector reads + parses
                         ↓
                    Adds security_score
                    Adds threat_level
                         ↓
                    Writes access_enriched.log
```

**Process**:
1. Angie writes JSON log with Level 1 enrichment
2. Vector reads file continuously
3. Parses JSON and calculates additional fields
4. Writes enhanced JSON to separate file
5. Independent pipeline (doesn't affect requests)

## Startup Dependencies

```yaml
# From compose.yml
services:
  angie:
    # No dependencies (starts first)

  oauth2-proxy:
    depends_on:
      - angie

  vector:
    depends_on:
      - angie

  fail2ban:
    # Independent (uses host network)
```

**Startup Order**:
1. Angie starts, creates log files
2. OAuth2-Proxy starts, ready for auth requests
3. Vector starts, begins reading logs
4. Fail2Ban starts, begins monitoring

## Security Boundaries

### Network Isolation

```
Internet
    ↓
  [Angie] ← Only exposed service
    ↓
  [angie_network] ← Internal communication
    ├─ OAuth2-Proxy (not exposed)
    └─ Vector (not exposed)

  [Fail2Ban] ← Host network (iptables access)
```

### Volume Security

```yaml
# Read-only mounts (cannot modify configs)
- ./angie/angie.conf:/etc/angie/angie.conf:ro
- ./angie/includes:/etc/angie/includes:ro
- ./modsec:/etc/angie/modsecurity:ro

# Read-write (logs only)
- ./logs:/var/log/angie
```

## Performance Considerations

### Rate Limiting (First Layer)

- Processed in shared memory (very fast)
- Applied before ModSecurity
- Prevents resource exhaustion

### ModSecurity (Second Layer)

- Runs in Angie worker process
- Analyzed per request
- Can be CPU intensive for complex rules
- Applied after rate limiting

### Logging (Asynchronous)

```nginx
access_log /var/log/angie/access.log json_enriched buffer=64k flush=5s;
```

- Buffered writes (64KB buffer)
- Periodic flush (5 seconds)
- Doesn't block request processing

### Fail2Ban (Offline Processing)

- Reads logs after they're written
- Doesn't affect request latency
- Bans apply to future requests

## High Availability Considerations

This template is designed for single-server deployment, but can be adapted:

**Shared Logs**:
- For multi-server: Use centralized logging (syslog, Loki)
- Fail2Ban needs access to all server logs

**Shared Bans**:
- For multi-server: Use external ban list (Redis, database)
- Or use network-level firewalls

**OAuth2-Proxy**:
- Can scale horizontally
- Uses cookie-based sessions (no shared state needed)
- Keycloak handles actual user sessions

## Next Steps

- Understand request processing: [Request Flow](request-flow.md)
- Learn security implementation: [Security Layers](security-layers.md)
- Configure the stack: [Configuration Guide](configuration.md)
- Monitor operations: [Logging System](logging.md)

# Logging System

This document describes the multi-level log enrichment pipeline and how to use logs for monitoring and debugging.

## Overview

The logging system in angie-modsecurity-docker operates at two levels:

```
Level 1: Angie Native Enrichment
  ├─ GeoIP data (country, city, coordinates)
  ├─ User-Agent parsing (browser, OS, device type)
  ├─ Security flags (suspicious patterns)
  ├─ Performance metrics (request time, size)
  └─ Business metrics (conversion events, A/B groups)
      ↓
  Writes: /var/log/angie/access.log (JSON format)
      ↓
Level 2: Vector Processing
  ├─ Reads Level 1 logs
  ├─ Parses JSON
  ├─ Calculates security_score
  ├─ Classifies threat_level
  └─ Adds metadata
      ↓
  Writes: /var/log/angie/access_enriched.log
```

## Log Files

### Location

All logs are stored in `/var/log/angie/` (shared volume):

```
/var/log/angie/
├── access.log              # Level 1: Enriched by Angie
├── access_enriched.log     # Level 2: Enhanced by Vector
└── error.log               # Errors + ModSecurity violations
```

### Access Pattern

```yaml
# From compose.yml

angie:
  volumes:
    - ./logs:/var/log/angie  # Read-write

fail2ban:
  volumes:
    - ./logs:/var/log/angie:ro  # Read-only

vector:
  volumes:
    - ./logs:/var/log/angie  # Read-write
```

## Level 1: Angie Enrichment

### Configuration

File: `angie/includes/logs/enrichment.conf`

#### GeoIP Lookup

```nginx
geoip2 /etc/angie/geoip/GeoLite2-City.mmdb {
    auto_reload 5m;
    $geoip2_country_code country iso_code;
    $geoip2_country_name country names en;
    $geoip2_city_name city names en;
    $geoip2_continent_code continent code;
    $geoip2_latitude location latitude;
    $geoip2_longitude location longitude;
    $geoip2_timezone location time_zone;
    $geoip2_postal_code postal code;
}
```

#### User-Agent Analysis

```nginx
# Device type detection
map $http_user_agent $device_type {
    default "desktop";
    ~*mobile "mobile";
    ~*tablet "tablet";
    ~*bot "bot";
}

# Browser detection
map $http_user_agent $browser {
    default "other";
    ~*chrome "chrome";
    ~*firefox "firefox";
    ~*safari "safari";
    ~*edge "edge";
}

# OS detection
map $http_user_agent $os {
    default "other";
    ~*windows "windows";
    ~*mac "macos";
    ~*linux "linux";
    ~*android "android";
    ~*ios "ios";
}

# Bot detection
map $http_user_agent $is_bot {
    default 0;
    ~*(bot|crawler|spider|scraper|curl|wget) 1;
}
```

#### Security Flags

```nginx
# Suspicious User-Agent
map $http_user_agent $suspicious_ua {
    default 0;
    ~*(sqlmap|nikto|nmap|masscan|metasploit|burp|acunetix) 1;
}

# Suspicious URL patterns
map $request_uri $suspicious_pattern {
    default 0;
    ~*(union.*select|insert.*into|drop.*table|\.\./) 1;
}

# Suspicious X-Forwarded-For (proxy chains)
map $http_x_forwarded_for $suspicious_xff {
    default 0;
    ~,.*,.*,.*,.*,.*,.*,.*,.*,.*,.* 1;  # 10+ IPs
}
```

#### Performance Classification

```nginx
# Response time categories
map $request_time $response_speed_category {
    ~^0\.0[0-1] "instant";      # <10ms
    ~^0\.0 "very_fast";          # <100ms
    ~^0\.[1-4] "fast";           # 100-499ms
    ~^0\.[5-9] "medium";         # 500-999ms
    ~^[1-2]\. "slow";            # 1-2s
    default "very_slow";         # >2s
}

# Response size categories
map $bytes_sent $response_size_category {
    ~^[0-9][0-9]?[0-9]?$ "tiny";        # <1KB
    ~^[0-9][0-9][0-9][0-9]$ "small";    # 1-9KB
    ~^[0-9][0-9][0-9][0-9][0-9]$ "medium";  # 10-99KB
    default "large";                     # >100KB
}
```

### JSON Log Format

File: `angie/includes/logs/log-formats.conf`

```nginx
log_format json_enriched escape=json '{'
    # Timestamp & ID
    '"timestamp":"$time_iso8601",'
    '"request_id":"$request_id",'

    # Client information
    '"client_ip":"$remote_addr",'
    '"client_port":"$remote_port",'
    '"client_xff":"$http_x_forwarded_for",'

    # GeoIP data
    '"geo_country_code":"$geoip2_country_code",'
    '"geo_country":"$geoip2_country_name",'
    '"geo_city":"$geoip2_city_name",'
    '"geo_continent":"$geoip2_continent_code",'
    '"geo_lat":"$geoip2_latitude",'
    '"geo_lon":"$geoip2_longitude",'
    '"geo_timezone":"$geoip2_timezone",'

    # User-Agent analysis
    '"ua_string":"$http_user_agent",'
    '"ua_device":"$device_type",'
    '"ua_browser":"$browser",'
    '"ua_os":"$os",'
    '"ua_is_bot":"$is_bot",'

    # Request details
    '"request_method":"$request_method",'
    '"request_uri":"$request_uri",'
    '"request_protocol":"$server_protocol",'
    '"request_host":"$host",'

    # Response details
    '"response_status":"$status",'
    '"response_bytes":"$bytes_sent",'
    '"response_body_bytes":"$body_bytes_sent",'
    '"response_size_category":"$response_size_category",'

    # Performance metrics
    '"perf_request_time":"$request_time",'
    '"perf_speed_category":"$response_speed_category",'
    '"perf_upstream_time":"$upstream_response_time",'

    # SSL/TLS
    '"ssl_protocol":"$ssl_protocol",'
    '"ssl_cipher":"$ssl_cipher",'

    # Security flags
    '"security_suspicious_ua":"$suspicious_ua",'
    '"security_suspicious_pattern":"$suspicious_pattern",'
    '"security_suspicious_xff":"$suspicious_xff",'

    # Server info
    '"server_name":"$server_name",'
    '"server_hostname":"$hostname"'
'}';
```

### Example Log Entry

```json
{
  "timestamp": "2025-12-06T15:30:45+03:00",
  "request_id": "a3f2b1c9d8e7f6a5",
  "client_ip": "203.0.113.45",
  "client_port": "54321",
  "client_xff": "",
  "geo_country_code": "US",
  "geo_country": "United States",
  "geo_city": "New York",
  "geo_continent": "NA",
  "geo_lat": "40.7128",
  "geo_lon": "-74.0060",
  "geo_timezone": "America/New_York",
  "ua_string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
  "ua_device": "desktop",
  "ua_browser": "chrome",
  "ua_os": "windows",
  "ua_is_bot": "0",
  "request_method": "GET",
  "request_uri": "/api/users?page=2",
  "request_protocol": "HTTP/2.0",
  "request_host": "example.com",
  "response_status": "200",
  "response_bytes": "3456",
  "response_body_bytes": "3200",
  "response_size_category": "small",
  "perf_request_time": "0.245",
  "perf_speed_category": "fast",
  "perf_upstream_time": "0.230",
  "ssl_protocol": "TLSv1.3",
  "ssl_cipher": "TLS_AES_256_GCM_SHA384",
  "security_suspicious_ua": "0",
  "security_suspicious_pattern": "0",
  "security_suspicious_xff": "0",
  "server_name": "example.com",
  "server_hostname": "angie"
}
```

## Level 2: Vector Enrichment

### Configuration

File: `vector/vector.toml`

```toml
# Source: Read Angie logs
[sources.angie_logs]
type = "file"
include = ["/var/log/angie/access.log"]
read_from = "end"

# Transform: Parse and enrich
[transforms.parse_json]
type = "remap"
inputs = ["angie_logs"]
source = '''
  # Parse JSON from Angie
  . = parse_json!(.message)

  # Add Vector metadata
  .meta_enriched_by = "vector"
  .meta_enriched_at = now()

  # Calculate security score
  score = 0
  if exists(.security_suspicious_ua) && .security_suspicious_ua == "1" {
    score = score + 5
  }
  if exists(.security_suspicious_pattern) && .security_suspicious_pattern == "1" {
    score = score + 7
  }
  if exists(.security_suspicious_xff) && .security_suspicious_xff == "1" {
    score = score + 3
  }
  .security_score = score

  # Classify threat level
  .security_threat_level = if score == 0 {
    "safe"
  } else if score < 5 {
    "low"
  } else if score < 10 {
    "medium"
  } else {
    "high"
  }
'''

# Sink: Write enriched logs
[sinks.enriched_logs]
type = "file"
inputs = ["parse_json"]
path = "/var/log/angie/access_enriched.log"
encoding.codec = "json"

[sinks.enriched_logs.buffer]
type = "disk"
max_size = 268435488  # 256 MB
```

### Security Score Calculation

```
Base Score: 0

Add points for suspicious indicators:
  + 5 points: Suspicious User-Agent (sqlmap, nikto, etc.)
  + 7 points: Suspicious URL pattern (SQLi, path traversal)
  + 3 points: Suspicious X-Forwarded-For (long proxy chain)

Examples:
  Normal request:     0 points → "safe"
  Bot scraping:       5 points → "medium"
  SQL injection:     12 points → "high"
  Combined attack:   15 points → "high"
```

### Enhanced Log Entry

After Vector processing:

```json
{
  "timestamp": "2025-12-06T15:30:45+03:00",
  "request_id": "a3f2b1c9d8e7f6a5",
  "client_ip": "203.0.113.100",
  "geo_country_code": "CN",
  "ua_string": "sqlmap/1.7.2",
  "ua_is_bot": "1",
  "request_uri": "/admin?id=1' OR '1'='1",
  "response_status": "403",
  "security_suspicious_ua": "1",
  "security_suspicious_pattern": "1",
  "security_suspicious_xff": "0",

  "security_score": 12,
  "security_threat_level": "high",
  "meta_enriched_by": "vector",
  "meta_enriched_at": "2025-12-06T15:30:45.123Z"
}
```

## Error Logs

### ModSecurity Violations

ModSecurity writes to `error.log`:

```
2025/12/06 15:35:22 [error] 42#42: *156 ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Rx' with parameter `(?i:(\s|;|'|")or(\s|;|'|").*?=.*?)` against variable `ARGS:id' (Value: `1' OR '1'='1' ) [file "/var/lib/angie/modsecurity/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: OR \x27 found within ARGS:id: 1\x27 OR \x271\x27=\x271"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.5"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"] [tag "PCI/6.5.2"], client: 203.0.113.100, server: example.com, request: "GET /admin?id=1' OR '1'='1 HTTP/2.0", host: "example.com"
```

### Angie Errors

General errors also in `error.log`:

```
2025/12/06 15:40:10 [warn] 42#42: *189 limiting requests, excess: 20.5 by zone "general", client: 203.0.113.45, server: example.com, request: "GET / HTTP/2.0", host: "example.com"

2025/12/06 15:41:05 [error] 42#42: *201 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.50, server: example.com, request: "GET /api/data HTTP/2.0", upstream: "http://172.18.0.5:8080/api/data", host: "example.com"
```

## Log Analysis

### Using jq for JSON Parsing

```bash
# Count requests by country
cat access.log | jq -r '.geo_country_code' | sort | uniq -c | sort -rn

# Find high threat requests
cat access_enriched.log | jq 'select(.security_threat_level == "high")'

# Average response time
cat access.log | jq -r '.perf_request_time' | awk '{sum+=$1; count++} END {print sum/count}'

# Top 10 IPs
cat access.log | jq -r '.client_ip' | sort | uniq -c | sort -rn | head -10

# Requests with suspicious patterns
cat access.log | jq 'select(.security_suspicious_pattern == "1")'

# Group by browser
cat access.log | jq -r '.ua_browser' | sort | uniq -c

# Failed requests (4xx, 5xx)
cat access.log | jq 'select(.response_status | tonumber >= 400)'
```

### Using grep for Error Logs

```bash
# Find all ModSecurity blocks
grep "ModSecurity: Access denied" error.log

# Extract blocked IPs
grep "ModSecurity: Access denied" error.log | grep -oP 'client: \K[0-9.]+'

# Count blocks by rule ID
grep "ModSecurity" error.log | grep -oP '\[id "\K[0-9]+' | sort | uniq -c

# Find rate limiting events
grep "limiting requests" error.log

# Backend connection errors
grep "connect() failed" error.log
```

### Real-Time Monitoring

```bash
# Tail access logs (pretty print)
tail -f access.log | jq '.'

# Watch for high-threat requests
tail -f access_enriched.log | jq 'select(.security_threat_level == "high")'

# Monitor ModSecurity blocks
tail -f error.log | grep "ModSecurity"

# Watch specific IP
tail -f access.log | jq 'select(.client_ip == "203.0.113.100")'
```

## Integration with Fail2Ban

### How Fail2Ban Uses Logs

```
Fail2Ban continuously tails logs:
  - /var/log/angie/access.log (for access patterns)
  - /var/log/angie/error.log (for ModSecurity)

Process:
  1. Read new log lines
  2. Apply regex filters
  3. Extract IP addresses
  4. Increment counters
  5. Check thresholds
  6. Ban if exceeded
```

### Example: ModSecurity Integration

```ini
# Jail configuration
[angie-modsecurity]
logpath = /var/log/angie/error.log
filter = angie-modsecurity

# Filter regex
failregex = ModSecurity: Access denied.*client: <HOST>,
```

**Process**:
```
Log entry:
  "2025/12/06 15:35:22 [error] ... ModSecurity: Access denied ... client: 203.0.113.100, ..."

Filter extracts:
  IP: 203.0.113.100

Counter:
  203.0.113.100: 1 violation

(After 2 more violations)
  203.0.113.100: 3 violations → BAN
```

## Log Rotation

### Docker Log Rotation

Docker automatically rotates container logs:

```yaml
# In compose.yml (optional)
services:
  angie:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Manual Log Rotation

Host-level logrotate:

```bash
# /etc/logrotate.d/angie-modsecurity-docker
/path/to/docker/angie-modsecurity-docker/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    missingok
    sharedscripts
    postrotate
        docker exec angie angie -s reopen > /dev/null 2>&1 || true
    endscript
}
```

## External Log Shipping

### Ship to Loki

```toml
# In vector.toml
[sinks.loki]
type = "loki"
inputs = ["parse_json"]
endpoint = "http://loki:3100"
encoding.codec = "json"
labels.job = "angie"
labels.environment = "production"
labels.server = "{{ server_name }}"
```

### Ship to Elasticsearch

```toml
[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["parse_json"]
endpoint = "http://elasticsearch:9200"
index = "angie-logs-%Y.%m.%d"
compression = "gzip"
```

### Ship to Syslog

```toml
[sinks.syslog]
type = "syslog"
inputs = ["parse_json"]
address = "syslog-server:514"
mode = "tcp"
encoding.codec = "json"
```

## Performance Monitoring

### Key Metrics from Logs

**Response Time Distribution**:
```bash
cat access.log | jq -r '.perf_request_time' | \
  awk '{if($1<0.1)a++;else if($1<0.5)b++;else if($1<1)c++;else d++}
       END{print "Fast(<100ms):",a,"Medium(<500ms):",b,"Slow(<1s):",c,"Very slow:",d}'
```

**Traffic by Country**:
```bash
cat access.log | jq -r '.geo_country_code' | sort | uniq -c | sort -rn | head -10
```

**Error Rate**:
```bash
total=$(cat access.log | wc -l)
errors=$(cat access.log | jq 'select(.response_status | tonumber >= 400)' | wc -l)
echo "Error rate: $(echo "scale=2; $errors * 100 / $total" | bc)%"
```

**Bot Traffic**:
```bash
cat access.log | jq -r '.ua_is_bot' | grep "1" | wc -l
```

## Debugging with Logs

### Trace a Specific Request

```bash
# Using request_id
request_id="a3f2b1c9d8e7f6a5"

# Find in access log
cat access.log | jq "select(.request_id == \"$request_id\")"

# Find in error log
grep "$request_id" error.log
```

### Investigate Failed Requests

```bash
# Find 5xx errors
cat access.log | jq 'select(.response_status | tonumber >= 500)'

# Check upstream issues
cat access.log | jq 'select(.perf_upstream_time == "" or .perf_upstream_time == null)'
```

### Security Incident Investigation

```bash
# Find all requests from suspicious IP
ip="203.0.113.100"
cat access.log | jq "select(.client_ip == \"$ip\")"

# Check threat level
cat access_enriched.log | jq "select(.client_ip == \"$ip\") | .security_threat_level"

# Find ModSecurity blocks for this IP
grep "client: $ip" error.log | grep "ModSecurity"
```

## Best Practices

1. **Buffer logs** in Angie for performance
   ```nginx
   access_log /var/log/angie/access.log json_enriched buffer=64k flush=5s;
   ```

2. **Rotate logs regularly** to prevent disk exhaustion

3. **Ship critical logs** to external systems for durability

4. **Index enriched logs** for fast searching

5. **Monitor log volume** as an early warning system

6. **Alert on high threat levels** from Vector

## Next Steps

- Understand log flow: [Request Flow](request-flow.md)
- Debug issues: [Troubleshooting](troubleshooting.md)
- Configure pipeline: [Configuration Guide](configuration.md)
- Review security: [Security Layers](security-layers.md)

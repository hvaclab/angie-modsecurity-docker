# Troubleshooting Guide

This document helps diagnose and resolve common issues in the integrated angie-modsecurity-docker stack.

## Diagnostic Approach

When troubleshooting, follow this systematic approach:

```
1. Identify the symptom
2. Determine which layer is affected
3. Check relevant logs
4. Verify configuration
5. Test in isolation
6. Apply fix
7. Verify resolution
```

## Quick Diagnostics

### Check All Container Status

```bash
docker compose ps
```

Expected output:
```
NAME            STATUS          PORTS
angie           Up 5 minutes    0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
oauth2-proxy    Up 5 minutes
vector          Up 5 minutes
fail2ban        Up 5 minutes
```

### Check Logs for All Services

```bash
# Angie access log
docker exec angie tail -20 /var/log/angie/access.log

# Angie error log
docker exec angie tail -20 /var/log/angie/error.log

# OAuth2-Proxy
docker logs --tail 20 oauth2-proxy

# Vector
docker logs --tail 20 vector

# Fail2Ban
docker logs --tail 20 fail2ban
```

## Issue Categories

### 1. Connection Issues

#### Symptom: Cannot connect to port 80/443

**Check 1: Container running**
```bash
docker compose ps angie
```

**Check 2: Port binding**
```bash
docker compose ps | grep angie
# Should show: 0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
```

**Check 3: Firewall**
```bash
# Check host firewall
sudo iptables -L -n | grep -E '80|443'

# Check Docker iptables
sudo iptables -t nat -L -n
```

**Check 4: Angie listening**
```bash
docker exec angie netstat -tlnp | grep -E ':80|:443'
```

**Solution**:
- If container not running: `docker compose up -d angie`
- If ports not bound: Check port conflicts with `sudo netstat -tlnp | grep -E ':80|:443'`
- If firewall blocking: `sudo ufw allow 80/tcp && sudo ufw allow 443/tcp`

#### Symptom: SSL/TLS errors

**Check 1: Certificate status**
```bash
# Test SSL connection
openssl s_client -connect example.com:443 -servername example.com

# Check certificate in Angie
docker exec angie openssl x509 -in /etc/ssl/certs/default-selfsigned.crt -text -noout
```

**Check 2: ACME status (if using Let's Encrypt)**
```bash
# Check ACME logs
docker exec angie tail -50 /var/log/angie/error.log | grep -i acme

# Check certificate files
docker exec angie ls -la /var/lib/angie/acme/
```

**Common Issues**:
- Using self-signed cert instead of ACME: Check virtual host config for `acme letsencrypt;`
- ACME challenge failing: Ensure port 80 is accessible and DNS is correct
- Certificate expired: ACME should auto-renew, check logs

**Solution**:
```nginx
# In virtual host config
server {
    listen 443 ssl;
    server_name example.com;

    # Use ACME (auto-renewal)
    acme letsencrypt;
    ssl_certificate     $acme_cert_letsencrypt;
    ssl_certificate_key $acme_cert_key_letsencrypt;
}
```

### 2. Rate Limiting Issues

#### Symptom: Legitimate traffic getting 429 errors

**Check 1: Rate limit logs**
```bash
docker exec angie tail -50 /var/log/angie/error.log | grep "limiting requests"
```

Example output:
```
2025/12/06 15:40:10 [warn] limiting requests, excess: 20.5 by zone "general", client: 203.0.113.45
```

**Check 2: Current limits**
```bash
docker exec angie grep -A 5 "limit_req_zone" /etc/angie/includes/security/rate-limiting.conf
```

**Check 3: Access log to see request pattern**
```bash
# Count requests per IP
docker exec angie cat /var/log/angie/access.log | \
  jq -r '.client_ip' | sort | uniq -c | sort -rn | head -10
```

**Solution**: Adjust rate limits

```nginx
# In rate-limiting.conf
# Increase rate from 10r/s to 50r/s
limit_req_zone $binary_remote_addr zone=general:10m rate=50r/s;

# Increase burst from 20 to 100
# In virtual host
limit_req zone=general burst=100 nodelay;
```

**Reload Angie**:
```bash
docker exec angie angie -t && docker exec angie angie -s reload
```

#### Symptom: Rate limiting not working

**Check 1: Verify zone is applied**
```bash
docker exec angie grep "limit_req zone" /etc/angie/conf.d/*.conf
```

**Check 2: Test rate limiting**
```bash
# Send rapid requests
for i in {1..50}; do
    curl -w "%{http_code}\n" -s -o /dev/null https://example.com/
done | sort | uniq -c
```

Should see mix of 200s and 429s.

**Check 3: Whitelist interference**
```bash
docker exec angie grep -A 10 "geo \$limit" /etc/angie/includes/security/rate-limiting.conf
```

If your IP is whitelisted, limits won't apply to you.

### 3. ModSecurity Issues

#### Symptom: False positives (legitimate requests blocked)

**Check 1: Find blocked request in logs**
```bash
docker exec angie grep "ModSecurity: Access denied" /var/log/angie/error.log | tail -5
```

Example:
```
ModSecurity: Access denied with code 403 (phase 2). Matched ... [id "942100"] [msg "SQL Injection Attack"] ... request: "GET /search?q=what's+new"
```

**Check 2: Identify the rule**
```
Rule ID: 942100
Message: SQL Injection Attack
Matched on: ARGS:q
Value: what's new
```

The single quote `'` in "what's" triggered SQL injection detection.

**Solution**: Add exclusion

```
# In modsec/exclusions.conf

# Disable rule 942100 for search queries
SecRule REQUEST_URI "@beginsWith /search" \
    "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"

# Or disable just for specific argument
SecRuleUpdateTargetById 942100 "!ARGS:q"
```

**Reload Angie**:
```bash
docker exec angie angie -s reload
```

#### Symptom: ModSecurity not blocking attacks

**Check 1: Verify ModSecurity is enabled**
```bash
docker exec angie grep "modsecurity on" /etc/angie/conf.d/*.conf
```

**Check 2: Test with known attack**
```bash
# Should return 403
curl "https://example.com/?id=1' OR '1'='1"
```

**Check 3: Verify CRS rules loaded**
```bash
docker exec angie ls -la /var/lib/angie/modsecurity/coreruleset/rules/
```

**Check 4: Check ModSecurity config**
```bash
docker exec angie cat /etc/angie/modsecurity/rules.conf
```

Should contain:
```
SecRuleEngine On
Include /var/lib/angie/modsecurity/coreruleset/rules/*.conf
```

**Solution**: Ensure proper configuration

```nginx
# In virtual host
modsecurity on;
modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
```

#### Symptom: ModSecurity causing performance issues

**Check 1: Monitor request times**
```bash
docker exec angie cat /var/log/angie/access.log | \
  jq -r '.perf_request_time' | \
  awk '{sum+=$1;count++} END {print "Average:",sum/count,"seconds"}'
```

**Check 2: Disable ModSecurity temporarily**
```nginx
# In location
modsecurity off;
```

Test if performance improves.

**Solution**: Optimize ModSecurity

```
# In modsec/rules.conf

# Disable response body inspection (CPU-intensive)
SecResponseBodyAccess Off

# Reduce paranoia level (if at 2 or higher)
# In CRS configuration
setvar:tx.paranoia_level=1

# Disable rules for static content
# In virtual host
location ~* \.(jpg|png|css|js)$ {
    modsecurity off;
    # ... rest of config
}
```

### 4. Fail2Ban Issues

#### Symptom: IPs not being banned

**Check 1: Fail2Ban status**
```bash
docker exec fail2ban fail2ban-client status
```

Should list active jails:
```
Status
|- Number of jail:      4
`- Jail list:   angie-modsecurity, angie-scan, angie-ddos, angie-bad-request
```

**Check 2: Check specific jail**
```bash
docker exec fail2ban fail2ban-client status angie-modsecurity
```

Look for:
```
Status for the jail: angie-modsecurity
|- Filter
|  |- Currently failed: 2
|  |- Total failed:     15
|  `- File list:        /var/log/angie/error.log
`- Actions
   |- Currently banned: 1
   |- Total banned:     3
   `- Banned IP list:   203.0.113.100
```

**Check 3: Test filter**
```bash
docker exec fail2ban fail2ban-regex /var/log/angie/error.log /data/filter.d/angie-modsecurity.conf
```

**Check 4: Verify log access**
```bash
docker exec fail2ban ls -la /var/log/angie/
docker exec fail2ban tail /var/log/angie/error.log
```

**Solution**: Common fixes

```ini
# In jail.d/angie.conf

# Check log path is correct
logpath = /var/log/angie/error.log  # Inside container

# Verify filter exists
filter = angie-modsecurity  # Must exist in filter.d/

# Lower threshold for testing
maxretry = 1
findtime = 60
bantime = 300
```

**Restart Fail2Ban**:
```bash
docker compose restart fail2ban
```

#### Symptom: Legitimate IPs being banned

**Check 1: Find ban reason**
```bash
docker exec fail2ban fail2ban-client status angie-scan | grep "203.0.113.50"
```

**Check 2: Check logs for this IP**
```bash
docker exec angie cat /var/log/angie/access.log | jq "select(.client_ip == \"203.0.113.50\")"
```

**Solution**: Whitelist the IP

```ini
# In jail.d/angie.conf
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16 203.0.113.50
```

**Unban and restart**:
```bash
docker exec fail2ban fail2ban-client set angie-scan unbanip 203.0.113.50
docker compose restart fail2ban
```

#### Symptom: Cannot modify iptables

**Error**: `iptables: command not found` or permission denied

**Check**: Fail2Ban uses host network mode

```bash
docker compose ps fail2ban
# Should show: network_mode: host
```

**Check**: Container has required capabilities

```yaml
# In compose.yml
fail2ban:
  network_mode: "host"
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

### 5. OAuth2-Proxy Issues

#### Symptom: Authentication loop (redirect loop)

**Check 1: OAuth2-Proxy logs**
```bash
docker logs oauth2-proxy | tail -50
```

**Check 2: Cookie settings**
```bash
docker exec oauth2-proxy env | grep COOKIE
```

**Common causes**:
- Cookie domain mismatch
- HTTPS not used (cookie set as secure)
- Cookie not being sent back

**Solution**:

```yaml
# In compose.yml
environment:
  - OAUTH2_PROXY_COOKIE_SECURE=true  # Requires HTTPS
  - OAUTH2_PROXY_COOKIE_DOMAINS=.example.com  # Match your domain
  - OAUTH2_PROXY_COOKIE_SAMESITE=lax  # Allow redirects
```

**Check browser cookies**: Ensure `_oauth2_proxy` cookie is set for your domain.

#### Symptom: 401 Unauthorized on protected paths

**Check 1: Test OAuth2 endpoint**
```bash
# Should redirect to login
curl -v https://example.com/admin

# Look for:
# < HTTP/2 302
# < location: /oauth2/start?rd=https://example.com/admin
```

**Check 2: Verify OAuth2-Proxy reachable**
```bash
docker exec angie curl -v http://oauth2-proxy:4180/ping
```

**Check 3: Check auth_request config**
```bash
docker exec angie grep -A 5 "auth_request" /etc/angie/conf.d/*.conf
```

Should have:
```nginx
auth_request /oauth2/auth;
error_page 401 = @oauth2_signin;
```

**Solution**: Ensure proper configuration

```nginx
# Include OAuth2 config
include /etc/angie/includes/auth/keycloak-auth.conf;

location /admin {
    auth_request /oauth2/auth;
    error_page 401 = @oauth2_signin;

    # ... rest of config
}
```

#### Symptom: Cannot reach Keycloak

**Check 1: OAuth2-Proxy logs**
```bash
docker logs oauth2-proxy | grep -i error
```

**Check 2: Keycloak URL**
```bash
docker exec oauth2-proxy env | grep KEYCLOAK_URL
```

**Check 3: Network connectivity**
```bash
docker exec oauth2-proxy curl -v $KEYCLOAK_URL/realms/$KEYCLOAK_REALM/.well-known/openid-configuration
```

**Solution**: Verify environment variables

```bash
# In .env
KEYCLOAK_URL=https://keycloak.example.com  # Must be accessible from container
KEYCLOAK_REALM=production
```

### 6. Logging Issues

#### Symptom: No logs being written

**Check 1: Log directory permissions**
```bash
ls -la logs/
```

Should be writable by container user (UID 1000 or angie user).

**Check 2: Disk space**
```bash
df -h logs/
```

**Check 3: Angie error log**
```bash
docker logs angie | grep -i error
```

**Solution**:
```bash
# Fix permissions
chmod 755 logs/

# Create log files if missing
touch logs/access.log logs/error.log
chmod 644 logs/*.log
```

#### Symptom: Vector not enriching logs

**Check 1: Vector status**
```bash
docker logs vector | tail -20
```

**Check 2: Verify Vector reading logs**
```bash
docker exec vector ls -la /var/log/angie/access.log
```

**Check 3: Check Vector config**
```bash
docker exec vector cat /etc/vector/vector.toml
```

**Check 4: Verify enriched log file**
```bash
ls -la logs/access_enriched.log
```

**Solution**: Restart Vector

```bash
docker compose restart vector

# Watch for processing
docker logs -f vector
```

### 7. Performance Issues

#### Symptom: High CPU usage

**Check 1: Identify the container**
```bash
docker stats --no-stream
```

**If Angie high CPU**:
- Check for DDoS: `docker exec angie tail -100 /var/log/angie/access.log | jq -r '.client_ip' | sort | uniq -c | sort -rn`
- Check ModSecurity load: Try disabling temporarily
- Check upstream response times: `docker exec angie cat /var/log/angie/access.log | jq -r '.perf_upstream_time'`

**If ModSecurity high CPU**:
- Lower paranoia level
- Disable response body inspection
- Add exclusions for static content

**Solution**: Optimize configuration

```nginx
# Disable ModSecurity for static files
location ~* \.(jpg|png|css|js)$ {
    modsecurity off;
    # ... rest
}

# Reduce logging verbosity
error_log /var/log/angie/error.log error;  # Only errors, not warnings
```

#### Symptom: Slow response times

**Check 1: Identify bottleneck**
```bash
docker exec angie cat /var/log/angie/access.log | \
  jq '{request_time: .perf_request_time, upstream_time: .perf_upstream_time, uri: .request_uri}'
```

If `upstream_time ≈ request_time`: Backend is slow
If `request_time >> upstream_time`: Angie processing is slow (likely ModSecurity)

**Check 2: Backend connectivity**
```bash
docker exec angie ping backend-hostname
```

**Solution**: Based on bottleneck

```nginx
# If backend slow: add timeouts
proxy_connect_timeout 5s;
proxy_send_timeout 10s;
proxy_read_timeout 30s;

# If ModSecurity slow: optimize or disable for specific paths
location /api/bulk-data {
    modsecurity off;  # Disable for high-volume endpoints
    # ... rest
}
```

## Emergency Procedures

### Complete Stack Failure

```bash
# Stop all containers
docker compose down

# Check Docker daemon
sudo systemctl status docker

# Check system resources
df -h
free -h

# Restart stack
docker compose up -d

# Monitor startup
docker compose logs -f
```

### Suspected Breach

```bash
# 1. Block all traffic temporarily (if needed)
docker compose stop angie

# 2. Review logs for suspicious activity
docker exec angie cat /var/log/angie/access.log | \
  jq 'select(.security_score > 10)'

# 3. Check all banned IPs
docker exec fail2ban fail2ban-client status | grep "Jail list"

# 4. Review ModSecurity blocks
docker exec angie grep "ModSecurity" /var/log/angie/error.log | tail -100

# 5. Export logs for analysis
docker cp angie:/var/log/angie /tmp/incident-logs-$(date +%Y%m%d)

# 6. If compromised, rebuild containers
docker compose down
docker compose pull
docker compose up -d
```

### Restore from Backup

```bash
# Stop stack
docker compose down

# Restore configs
cp -r backup/angie/ angie/
cp -r backup/modsec/ modsec/
cp backup/.env .env

# Rebuild containers
docker compose build --no-cache

# Start stack
docker compose up -d
```

## Debugging Checklist

When facing an issue:

- [ ] Check container status: `docker compose ps`
- [ ] Check relevant logs: Access log, error log, container logs
- [ ] Verify configuration syntax: `docker exec angie angie -t`
- [ ] Test in isolation: Disable other layers temporarily
- [ ] Check network connectivity: Between containers
- [ ] Verify file permissions: Logs, configs
- [ ] Check disk space: `df -h`
- [ ] Review recent changes: Git log, config diff
- [ ] Test with curl: Isolate browser issues
- [ ] Monitor real-time: `docker logs -f`, `tail -f`

## Getting Help

If issues persist:

1. **Gather information**:
   ```bash
   # System info
   docker version
   docker compose version
   uname -a

   # Container info
   docker compose ps
   docker compose logs > debug-logs.txt

   # Configuration
   docker exec angie angie -T > angie-config.txt
   ```

2. **Review documentation**:
   - [Architecture](architecture.md) - Understand component relationships
   - [Request Flow](request-flow.md) - Trace request processing
   - [Security Layers](security-layers.md) - Review security implementation
   - [Configuration Guide](configuration.md) - Verify settings

3. **Check project issues**: GitHub issues for known problems

4. **Ask for help**: Provide gathered information when asking

## Useful Commands Reference

```bash
# Container management
docker compose up -d                    # Start stack
docker compose down                     # Stop stack
docker compose restart angie            # Restart specific service
docker compose logs -f angie            # Follow logs

# Angie
docker exec angie angie -t              # Test configuration
docker exec angie angie -s reload       # Reload configuration
docker exec angie angie -V              # Show version
docker exec angie ps aux                # Show processes

# Fail2Ban
docker exec fail2ban fail2ban-client status                    # Show all jails
docker exec fail2ban fail2ban-client status angie-modsecurity  # Jail details
docker exec fail2ban fail2ban-client set JAIL unbanip IP       # Unban IP
docker exec fail2ban fail2ban-client reload                    # Reload config

# Logs
docker exec angie tail -f /var/log/angie/access.log            # Follow access log
docker exec angie grep "403" /var/log/angie/access.log         # Find 403s
cat logs/access.log | jq '.' | less                            # Pretty print JSON
cat logs/access.log | jq 'select(.security_score > 10)'        # Filter high scores

# OAuth2-Proxy
docker logs oauth2-proxy               # View logs
docker restart oauth2-proxy            # Restart service

# Vector
docker logs vector                     # View logs
docker exec vector vector validate --config-toml /etc/vector/vector.toml  # Validate config
```

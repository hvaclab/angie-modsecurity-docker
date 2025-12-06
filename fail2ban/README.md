# Fail2Ban Configuration for Angie

## Active Protections (5 jails)

### 1. **angie-bad-request** - Bad HTTP Requests
- **Protects:** Against malformed/malicious HTTP requests
- **Blocks:** HTTP 400/444 errors
- **Parameters:**
  - 5 errors in 5 minutes → ban for 1 hour
- **Log:** `/var/log/angie/access.log`

### 2. **angie-modsecurity** - WAF Protection
- **Protects:** Against SQL injection, XSS, RCE and other attacks
- **Blocks:** Requests blocked by ModSecurity
- **Parameters:**
  - 3 WAF triggers in 5 minutes → ban for 2 hours
- **Log:** `/var/log/angie/error.log`

### 3. **angie-scan** - Vulnerability Scanning
- **Protects:** Against automated scanners
- **Blocks:** Suspicious 404 errors (.php, .env, etc)
- **Parameters:**
  - 10 suspicious 404s in 10 minutes → ban for 24 hours
- **Log:** `/var/log/angie/access.log`

### 4. **angie-ddos** - HTTP Flood Protection
- **Protects:** Against DDoS attacks
- **Blocks:** Too frequent requests
- **Parameters:**
  - 100 requests in 1 minute → ban for 10 minutes
- **Log:** `/var/log/angie/access.log`

### 5. **angie-badbots** - Bad Bots
- **Protects:** Against malicious bots and crawlers
- **Blocks:** Known bad user agents
- **Parameters:**
  - 1 match → ban for 24 hours
- **Log:** `/var/log/angie/access.log`

## Management Commands

### Check Status
```bash
# Overall status
docker exec fail2ban fail2ban-client status

# Specific jail details
docker exec fail2ban fail2ban-client status angie-bad-request

# List banned IPs
docker exec fail2ban fail2ban-client banned
```

### Unban IP
```bash
# Unban from all jails
docker exec fail2ban fail2ban-client unban 1.2.3.4

# Unban from specific jail
docker exec fail2ban fail2ban-client set angie-bad-request unbanip 1.2.3.4
```

### Manual Ban
```bash
# Ban IP
docker exec fail2ban fail2ban-client set angie-bad-request banip 1.2.3.4

# Restart Fail2Ban
docker restart fail2ban
```

### View Logs
```bash
# Fail2Ban logs
docker logs fail2ban -f

# Angie logs (source for Fail2Ban)
docker logs angie -f
```

## Configuration Structure

```
fail2ban/
├── filter.d/               # Filters (regex patterns)
│   ├── angie-bad-request.conf
│   ├── angie-badbots.conf
│   ├── angie-ddos.conf
│   ├── angie-modsecurity.conf
│   └── angie-scan.conf
├── jail.d/                 # Jail configurations
│   └── angie.conf         # All rules
├── db/                    # Ban database
│   └── .gitkeep
└── jail.local             # Global settings
```

## Configuration

### Changing Parameters

Edit `fail2ban/jail.d/angie.conf`:

```ini
[angie-bad-request]
maxretry = 5      # Number of attempts
findtime = 300    # Time window (seconds)
bantime = 3600    # Ban duration (seconds)
```

After changes:
```bash
docker restart fail2ban
```

### Adding IPs to Whitelist

Edit `fail2ban/jail.d/angie.conf`:

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 172.18.0.0/16 YOUR_IP_HERE
```

### Testing Filter

```bash
# Check if filter matches log line
docker exec fail2ban fail2ban-regex /var/log/angie/access.log /etc/fail2ban/filter.d/angie-bad-request.conf
```

## Monitoring

### Statistics
```bash
# Total banned count
docker exec fail2ban fail2ban-client status | grep "Total banned"

# Detailed stats for all jails
for jail in angie-bad-request angie-modsecurity angie-scan angie-ddos angie-badbots; do
  echo "=== $jail ==="
  docker exec fail2ban fail2ban-client status $jail | grep -E "failed|banned"
done
```

### Activity Log
```bash
# Recent bans
docker exec fail2ban tail -50 /var/log/fail2ban.log | grep Ban

# Recent unbans
docker exec fail2ban tail -50 /var/log/fail2ban.log | grep Unban
```

## Common Scenarios

### Scenario 1: Locked Out
If you trigger 5+ bad requests, you'll be banned for 1 hour.

**Solution:**
```bash
# Find your IP
curl ifconfig.me

# Unban yourself
docker exec fail2ban fail2ban-client unban YOUR_IP
```

### Scenario 2: Under Attack
```bash
# Check who's attacking
docker exec fail2ban fail2ban-client status angie-ddos

# Permanent ban (add to iptables)
iptables -I INPUT -s ATTACKER_IP -j DROP
```

### Scenario 3: False Positive
```bash
# Temporarily disable jail
docker exec fail2ban fail2ban-client stop angie-scan

# Re-enable
docker exec fail2ban fail2ban-client start angie-scan
```

## Backup

```bash
# Create backup
tar -czf fail2ban-backup-$(date +%Y%m%d).tar.gz fail2ban/

# Restore
tar -xzf fail2ban-backup-20241111.tar.gz
docker restart fail2ban
```

## Notes

- Fail2Ban works at iptables level
- Bans apply to ALL ports (not just 80/443)
- Ban database is saved in `db/fail2ban.sqlite3`
- Logs are rotated automatically
- Fail2Ban starts automatically with Docker

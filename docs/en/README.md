# angie-modsecurity-docker Documentation

Welcome to the angie-modsecurity-docker documentation. This documentation describes how the integrated security stack works together to provide comprehensive protection for your web applications.

## What is angie-modsecurity-docker?

angie-modsecurity-docker is a production-ready, Docker-based web server stack that combines multiple security and performance components into a unified system. It's not just a collection of tools - it's a carefully orchestrated integration where each component enhances the others.

## Key Integration Points

This stack consists of four main components that work together:

1. **Angie** - High-performance web server with ModSecurity integration
2. **ModSecurity** - Web Application Firewall (WAF) embedded in Angie
3. **Fail2Ban** - IP-based banning system that reads Angie logs
4. **Vector** - Log enrichment pipeline that adds intelligence to raw logs
5. **OAuth2-Proxy** - Authentication layer for Keycloak integration

## Architecture Overview

```
                                  Internet
                                     |
                                     v
                        +------------------------+
                        |   Angie (Port 80/443)  |
                        |  - Rate Limiting       |
                        |  - ModSecurity WAF     |
                        |  - GeoIP Enrichment    |
                        |  - SSL/TLS (HTTP/3)    |
                        +------------------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
           +-----------------+              +------------------+
           | OAuth2-Proxy    |              | Backend Apps     |
           | (Keycloak auth) |              | (Proxied)        |
           +-----------------+              +------------------+
                    |
                    v
           +------------------+
           | Logs Directory   |
           | /var/log/angie/  |
           +------------------+
                    |
        +-----------+------------+
        |                        |
        v                        v
   +----------+            +-----------+
   | Fail2Ban |            | Vector    |
   | (Reads)  |            | (Enriches)|
   +----------+            +-----------+
        |                        |
        v                        v
   [IP Bans]              [Enhanced Logs]
```

## Documentation Structure

### Core Concepts

- **[Architecture](architecture.md)** - How components are connected and communicate
- **[Request Flow](request-flow.md)** - Journey of a request through all security layers
- **[Security Layers](security-layers.md)** - Defense-in-depth strategy and layer interaction

### Configuration & Operations

- **[Configuration Guide](configuration.md)** - How to configure the integrated stack
- **[Logging System](logging.md)** - Multi-level log enrichment and processing
- **[Troubleshooting](troubleshooting.md)** - Debugging issues in the integrated system

## Quick Start

1. **Understand the Architecture** - Read [Architecture](architecture.md) to understand component relationships
2. **Follow the Request** - See [Request Flow](request-flow.md) to understand data processing
3. **Configure Your Stack** - Use [Configuration Guide](configuration.md) to customize settings
4. **Monitor & Debug** - Check [Logging](logging.md) and [Troubleshooting](troubleshooting.md) for operations

## Key Features

### Multi-Layer Security

- **Layer 1 (Angie)**: Rate limiting, geo-blocking, header validation
- **Layer 2 (ModSecurity)**: WAF rules, OWASP CRS, SQL injection detection
- **Layer 3 (Fail2Ban)**: Pattern-based IP banning from aggregated logs
- **Layer 4 (OAuth2-Proxy)**: Authentication and authorization for protected resources

See [Security Layers](security-layers.md) for detailed interaction patterns.

### Intelligent Logging

- **Level 1 (Angie)**: Log enrichment with GeoIP, User-Agent analysis, security flags
- **Level 2 (Vector)**: Advanced processing, security scoring, threat classification

See [Logging System](logging.md) for complete pipeline details.

### Performance Optimizations

- **HTTP/3 (QUIC)** support for faster connections
- **Brotli/Zstd** compression for reduced bandwidth
- **Rate limiting** to prevent resource exhaustion
- **Caching** at multiple levels

## Integration Philosophy

Unlike standalone deployments, this stack is designed around these principles:

1. **Data Flow** - Each component enriches data for the next layer
2. **Shared State** - Logs directory is the communication hub
3. **Defense in Depth** - Multiple layers catch different attack types
4. **Progressive Enhancement** - Each layer adds intelligence without blocking previous ones

## What Makes This Different?

Most tutorials show you how to configure Angie, ModSecurity, or Fail2Ban separately. This documentation focuses on:

- How Angie passes requests to ModSecurity
- How ModSecurity logs are read by Fail2Ban
- How Vector enriches logs with additional context
- How OAuth2-Proxy integrates with Angie's auth system
- How to debug issues that span multiple components

## Getting Help

If you encounter issues:

1. Check [Troubleshooting](troubleshooting.md) for common integration problems
2. Review [Request Flow](request-flow.md) to understand where the issue occurs
3. Examine [Logging System](logging.md) to find relevant log entries
4. Refer to [Architecture](architecture.md) to understand component relationships

## Next Steps

- New users: Start with [Architecture](architecture.md)
- Configuring the stack: Go to [Configuration Guide](configuration.md)
- Debugging issues: Check [Troubleshooting](troubleshooting.md)
- Understanding security: Read [Security Layers](security-layers.md)

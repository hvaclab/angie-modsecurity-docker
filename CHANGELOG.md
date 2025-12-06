# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-07

### Added
- Angie 1.10.3 web server (nginx fork) with ModSecurity WAF
- OWASP Core Rule Set 4.18.0 (825+ security rules)
- Multi-layered security: ModSecurity → Fail2Ban → Rate Limiting
- GeoIP enrichment with auto-download on first start
- Auto-generated SSL certificates and DH parameters (2048-bit)
- HTTP/2 and HTTP/3 (QUIC) support
- Comprehensive JSON logging with 70+ fields
- Security scoring system (0-15 threat levels)
- GitHub Actions CI/CD pipeline
- Bilingual documentation (EN/RU)
- Docker Compose configuration for dev and prod modes
- Makefile with helper commands

### Security
- TLS 1.2/1.3 only (TLS 1.0/1.1 disabled)
- Modern cipher suites (ECDHE, AES-GCM, ChaCha20)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Fail2Ban jails for bad requests, scans, DDoS, ModSecurity alerts

[1.0.0]: https://github.com/hvaclab/angie-modsecurity-docker/releases/tag/v1.0.0

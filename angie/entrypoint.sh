#!/bin/sh
# ==============================================================================
# Angie Entrypoint Script
# ==============================================================================
# Automatically downloads/updates required files on container start:
# - GeoIP database (if missing or older than 30 days)
# - DH parameters (if missing)
# - Self-signed SSL certificate (if missing)
# ==============================================================================

set -e

# Configuration paths
GEOIP_DIR="/etc/angie/geoip"
GEOIP_FILE="$GEOIP_DIR/GeoLite2-City.mmdb"
GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"

SSL_DIR="/etc/angie/ssl"
DH_FILE="$SSL_DIR/dhparam.pem"
CERT_FILE="$SSL_DIR/default-selfsigned.crt"
KEY_FILE="$SSL_DIR/default-selfsigned.key"
DH_BITS=2048

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1"; }

# ==============================================================================
# GeoIP Database
# ==============================================================================
download_geoip() {
    log_info "Downloading GeoIP database..."
    mkdir -p "$GEOIP_DIR"

    if curl -sfL "$GEOIP_URL" -o "$GEOIP_FILE.tmp" 2>/dev/null; then
        mv "$GEOIP_FILE.tmp" "$GEOIP_FILE"
        log_info "GeoIP database downloaded ($(du -h "$GEOIP_FILE" | cut -f1))"
        return 0
    else
        rm -f "$GEOIP_FILE.tmp"
        log_error "Failed to download GeoIP database"
        return 1
    fi
}

check_geoip() {
    if [ ! -f "$GEOIP_FILE" ]; then
        log_warn "GeoIP database not found"
        download_geoip || log_warn "Continuing without GeoIP (some features may fail)"
        return
    fi

    # Auto-update if enabled and file is old
    if [ "$AUTO_UPDATE_GEOIP" = "true" ]; then
        FILE_AGE=$(( ($(date +%s) - $(stat -c %Y "$GEOIP_FILE" 2>/dev/null || echo 0)) / 86400 ))
        MAX_AGE="${GEOIP_MAX_AGE_DAYS:-30}"
        if [ "$FILE_AGE" -gt "$MAX_AGE" ]; then
            log_info "GeoIP is $FILE_AGE days old, updating..."
            download_geoip || log_warn "Update failed, using existing"
        else
            log_info "GeoIP OK ($FILE_AGE days old)"
        fi
    else
        log_info "GeoIP found ($(du -h "$GEOIP_FILE" | cut -f1))"
    fi
}

# ==============================================================================
# DH Parameters
# ==============================================================================
check_dhparam() {
    mkdir -p "$SSL_DIR"

    if [ ! -f "$DH_FILE" ]; then
        log_warn "DH parameters not found, generating ($DH_BITS bit)..."
        openssl dhparam -out "$DH_FILE" "$DH_BITS" 2>/dev/null
        log_info "DH parameters generated"
        return
    fi

    # Verify strength (extract first number before "bit")
    DH_SIZE=$(openssl dhparam -in "$DH_FILE" -text -noout 2>/dev/null | head -1 | sed 's/[^0-9]//g' || echo "0")
    if [ -z "$DH_SIZE" ] || [ "$DH_SIZE" -lt 2048 ]; then
        log_warn "DH params too weak ($DH_SIZE bit), regenerating..."
        openssl dhparam -out "$DH_FILE" "$DH_BITS" 2>/dev/null
        log_info "DH parameters regenerated"
    else
        log_info "DH parameters OK ($DH_SIZE bit)"
    fi
}

# ==============================================================================
# SSL Certificates
# ==============================================================================
check_ssl_certs() {
    mkdir -p "$SSL_DIR"

    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
        log_warn "SSL certificate not found, generating self-signed..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -subj "/CN=localhost/O=Angie/C=US" 2>/dev/null
        log_info "Self-signed certificate generated"
    else
        log_info "SSL certificates found"
    fi
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    echo ""
    echo "=============================================="
    echo "  Angie ModSecurity Docker - Starting"
    echo "=============================================="
    echo ""

    check_geoip
    check_dhparam
    check_ssl_certs

    echo ""
    log_info "Pre-flight checks complete, starting Angie..."
    echo ""

    exec "$@"
}

main "$@"

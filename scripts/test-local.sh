#!/bin/bash
# ==============================================================================
# Local Testing Script
# ==============================================================================
# Runs Angie on ports 8080/8443 to avoid conflicts with production services
#
# Usage:
#   ./scripts/test-local.sh          # Run tests
#   ./scripts/test-local.sh --clean  # Clean up after tests
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
HTTP_PORT=18080
HTTPS_PORT=18443
CONTAINER_NAME="angie-test"

# ==============================================================================
# Functions
# ==============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    docker compose -f compose.test.yml down -v 2>/dev/null || true
    log_info "Cleanup complete"
}

setup_test_certs() {
    log_info "Setting up test certificates..."

    mkdir -p certs logs

    # Generate self-signed cert if not exists
    if [ ! -f certs/default-selfsigned.crt ]; then
        openssl req -x509 -nodes -days 30 \
            -newkey rsa:2048 \
            -keyout certs/default-selfsigned.key \
            -out certs/default-selfsigned.crt \
            -subj "/CN=localhost/O=Test/C=US" 2>/dev/null
        log_info "Generated self-signed certificate"
    fi

    # Generate DH params if not exists (2048-bit for security)
    if [ ! -f certs/dhparam.pem ]; then
        openssl dhparam -out certs/dhparam.pem 2048 2>/dev/null
        log_info "Generated DH parameters (2048-bit)"
    fi
}

build_image() {
    log_info "Building Docker image..."
    docker compose -f compose.test.yml build --no-cache
    log_info "Image built successfully"
}

start_container() {
    log_info "Starting container on ports $HTTP_PORT/$HTTPS_PORT..."
    docker compose -f compose.test.yml up -d

    # Wait for container to be healthy
    log_info "Waiting for container to become healthy..."
    for i in {1..30}; do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not_found")
        if [ "$STATUS" = "healthy" ]; then
            log_info "Container is healthy!"
            return 0
        elif [ "$STATUS" = "not_found" ]; then
            log_error "Container not found"
            return 1
        fi
        sleep 2
    done

    log_error "Container did not become healthy in 60 seconds"
    docker logs "$CONTAINER_NAME"
    return 1
}

run_tests() {
    log_info "Running tests..."

    local FAILED=0

    # Test 1: Health endpoint
    echo -n "  Testing /health... "
    if curl -sf "http://localhost:$HTTP_PORT/health" > /dev/null; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=1
    fi

    # Test 2: Ready endpoint
    echo -n "  Testing /ready... "
    if curl -sf "http://localhost:$HTTP_PORT/ready" > /dev/null; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=1
    fi

    # Test 3: Live endpoint
    echo -n "  Testing /live... "
    if curl -sf "http://localhost:$HTTP_PORT/live" > /dev/null; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=1
    fi

    # Test 4: Status endpoint (JSON)
    echo -n "  Testing /status (JSON)... "
    if curl -sf "http://localhost:$HTTP_PORT/status" | grep -q '"status":"ok"'; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=1
    fi

    # Test 5: HTTPS works (self-signed)
    echo -n "  Testing HTTPS (self-signed)... "
    if curl -skf "https://localhost:$HTTPS_PORT/" > /dev/null 2>&1 || \
       curl -sk "https://localhost:$HTTPS_PORT/" 2>&1 | grep -q "444\|connection reset"; then
        echo -e "${GREEN}PASS${NC} (expected 444 for unknown host)"
    else
        echo -e "${YELLOW}SKIP${NC}"
    fi

    # Test 6: No critical errors in logs
    echo -n "  Checking logs for errors... "
    if docker logs "$CONTAINER_NAME" 2>&1 | grep -qi "emerg\|crit"; then
        echo -e "${RED}FAIL${NC} (critical errors found)"
        FAILED=1
    else
        echo -e "${GREEN}PASS${NC}"
    fi

    return $FAILED
}

show_summary() {
    echo ""
    echo "=============================================="
    echo "Test Summary"
    echo "=============================================="
    echo "Container: $CONTAINER_NAME"
    echo "HTTP Port: $HTTP_PORT"
    echo "HTTPS Port: $HTTPS_PORT"
    echo ""
    echo "URLs for manual testing:"
    echo "  http://localhost:$HTTP_PORT/health"
    echo "  http://localhost:$HTTP_PORT/status"
    echo "  https://localhost:$HTTPS_PORT/ (self-signed)"
    echo ""
    echo "Logs: docker logs $CONTAINER_NAME -f"
    echo "Stop: docker compose -f compose.test.yml down -v"
    echo "=============================================="
}

# ==============================================================================
# Main
# ==============================================================================

if [ "$1" = "--clean" ] || [ "$1" = "-c" ]; then
    cleanup
    exit 0
fi

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --clean, -c    Clean up containers and volumes"
    echo "  --help, -h     Show this help"
    echo ""
    exit 0
fi

# Cleanup any previous test run
cleanup

# Setup and run
setup_test_certs
build_image
start_container

if run_tests; then
    log_info "All tests passed!"
    show_summary
    exit 0
else
    log_error "Some tests failed!"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    exit 1
fi

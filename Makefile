# ==============================================================================
# angie-modsecurity-docker - Makefile
# ==============================================================================
# Usage: make [target]
# Run 'make help' for available commands
# ==============================================================================

.PHONY: help build up down restart logs shell test clean clean-all dev prod status health certs geoip lint

# Default target
.DEFAULT_GOAL := help

# Colors for output
YELLOW := \033[1;33m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

# Project settings
PROJECT_NAME := angie-modsecurity-docker
COMPOSE_FILE := compose.yml
COMPOSE_TEST_FILE := compose.test.yml

# ==============================================================================
# HELP
# ==============================================================================

help: ## Show this help message
	@echo ""
	@echo "$(GREEN)$(PROJECT_NAME)$(NC) - Available commands:"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E '(dev|test|lint)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Production:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E '(prod|up|down|restart)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -vE '(dev|test|lint|prod|up|down|restart)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ==============================================================================
# DEVELOPMENT MODE (ports 18080/18443)
# ==============================================================================

dev: certs geoip ## Start in DEV mode (ports 18080/18443)
	@echo "$(GREEN)Starting in DEVELOPMENT mode...$(NC)"
	@docker compose -f $(COMPOSE_TEST_FILE) up -d --build
	@echo ""
	@echo "$(GREEN)Dev server running:$(NC)"
	@echo "  HTTP:  http://localhost:18080"
	@echo "  HTTPS: https://localhost:18443"
	@echo "  Health: http://localhost:18080/health"
	@echo ""

dev-down: ## Stop DEV mode
	@echo "$(YELLOW)Stopping DEV containers...$(NC)"
	@docker compose -f $(COMPOSE_TEST_FILE) down -v

dev-logs: ## Show DEV logs
	@docker compose -f $(COMPOSE_TEST_FILE) logs -f

dev-shell: ## Shell into DEV container
	@docker exec -it angie-test sh

# ==============================================================================
# PRODUCTION MODE (ports 80/443)
# ==============================================================================

prod: check-env certs ## Start in PRODUCTION mode (ports 80/443)
	@echo "$(GREEN)Starting in PRODUCTION mode...$(NC)"
	@docker compose -f $(COMPOSE_FILE) up -d --build
	@echo ""
	@echo "$(GREEN)Production server running on ports 80/443$(NC)"

prod-down: ## Stop PRODUCTION mode
	@echo "$(YELLOW)Stopping PRODUCTION containers...$(NC)"
	@docker compose -f $(COMPOSE_FILE) down

# Aliases for production
up: prod ## Alias for 'prod'
down: prod-down ## Alias for 'prod-down'

restart: ## Restart production services
	@echo "$(YELLOW)Restarting services...$(NC)"
	@docker compose -f $(COMPOSE_FILE) restart

reload: ## Reload Angie configuration (no downtime)
	@echo "$(YELLOW)Reloading Angie config...$(NC)"
	@docker exec angie-web angie -t && docker exec angie-web angie -s reload
	@echo "$(GREEN)Config reloaded successfully$(NC)"

# ==============================================================================
# TESTING
# ==============================================================================

test: ## Run local tests (starts dev, runs tests, stops)
	@echo "$(GREEN)Running tests...$(NC)"
	@./scripts/test-local.sh

test-ci: ## Run CI-style tests
	@echo "$(GREEN)Running CI tests...$(NC)"
	@docker compose -f $(COMPOSE_TEST_FILE) build
	@docker compose -f $(COMPOSE_TEST_FILE) up -d
	@sleep 10
	@curl -sf http://localhost:18080/health && echo " $(GREEN)✓ health$(NC)" || echo " $(RED)✗ health$(NC)"
	@curl -sf http://localhost:18080/ready && echo " $(GREEN)✓ ready$(NC)" || echo " $(RED)✗ ready$(NC)"
	@curl -sf http://localhost:18080/status && echo " $(GREEN)✓ status$(NC)" || echo " $(RED)✗ status$(NC)"
	@docker compose -f $(COMPOSE_TEST_FILE) down -v

lint: ## Lint configuration files
	@echo "$(GREEN)Linting...$(NC)"
	@docker compose -f $(COMPOSE_FILE) config --quiet && echo "$(GREEN)✓ compose.yml$(NC)"
	@docker compose -f $(COMPOSE_TEST_FILE) config --quiet && echo "$(GREEN)✓ compose.test.yml$(NC)"
	@docker run --rm -i hadolint/hadolint < angie/Dockerfile || true

# ==============================================================================
# UTILITIES
# ==============================================================================

build: ## Build Docker images
	@echo "$(GREEN)Building images...$(NC)"
	@docker compose -f $(COMPOSE_FILE) build

logs: ## Show production logs
	@docker compose -f $(COMPOSE_FILE) logs -f

shell: ## Shell into production Angie container
	@docker exec -it angie-web sh

status: ## Show container status
	@echo "$(GREEN)Container status:$(NC)"
	@docker compose -f $(COMPOSE_FILE) ps 2>/dev/null || docker compose -f $(COMPOSE_TEST_FILE) ps

health: ## Check health endpoints
	@echo "$(GREEN)Checking health...$(NC)"
	@curl -sf http://localhost:18080/health 2>/dev/null && echo " DEV (18080): $(GREEN)healthy$(NC)" || \
	 curl -sf http://localhost:80/health 2>/dev/null && echo " PROD (80): $(GREEN)healthy$(NC)" || \
	 echo " $(RED)No healthy server found$(NC)"

clean: ## Remove all containers, volumes, and images
	@echo "$(RED)Cleaning up...$(NC)"
	@docker compose -f $(COMPOSE_FILE) down -v --rmi local 2>/dev/null || true
	@docker compose -f $(COMPOSE_TEST_FILE) down -v --rmi local 2>/dev/null || true
	@rm -f certs/*.pem certs/*.crt certs/*.key 2>/dev/null || true
	@rm -f logs/*.log logs/*.json logs/*.gz 2>/dev/null || true
	@rm -f geoip/*.mmdb 2>/dev/null || true
	@rm -f fail2ban/db/*.sqlite3* 2>/dev/null || true
	@docker image prune -f 2>/dev/null || true
	@echo "$(GREEN)Cleanup complete$(NC)"

clean-all: ## Full cleanup including Docker cache
	@$(MAKE) clean
	@docker builder prune -f 2>/dev/null || true
	@echo "$(GREEN)Full cleanup complete$(NC)"

# ==============================================================================
# SETUP
# ==============================================================================

certs: ## Generate self-signed certificates (if missing)
	@mkdir -p certs
	@if [ ! -f certs/dhparam.pem ]; then \
		echo "$(YELLOW)Generating DH parameters (this takes a minute)...$(NC)"; \
		openssl dhparam -out certs/dhparam.pem 2048; \
	fi
	@if [ ! -f certs/default-selfsigned.crt ]; then \
		echo "$(YELLOW)Generating self-signed certificate...$(NC)"; \
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
			-keyout certs/default-selfsigned.key \
			-out certs/default-selfsigned.crt \
			-subj "/CN=localhost/O=Dev/C=US"; \
	fi
	@echo "$(GREEN)✓ Certificates ready$(NC)"

geoip: ## Download GeoIP database (if missing)
	@mkdir -p geoip
	@if [ ! -f geoip/GeoLite2-City.mmdb ]; then \
		echo "$(YELLOW)Downloading GeoIP database...$(NC)"; \
		curl -sL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" -o geoip/GeoLite2-City.mmdb; \
		echo "$(GREEN)✓ GeoIP database downloaded$(NC)"; \
	else \
		echo "$(GREEN)✓ GeoIP database exists$(NC)"; \
	fi

setup: certs geoip ## Initial setup (certs + geoip)
	@cp -n .env.example .env 2>/dev/null || true
	@echo "$(GREEN)Setup complete! Edit .env and run 'make dev' or 'make prod'$(NC)"

check-env: ## Check if .env exists
	@if [ ! -f .env ]; then \
		echo "$(RED)Error: .env file not found!$(NC)"; \
		echo "Run: cp .env.example .env"; \
		exit 1; \
	fi

# ==============================================================================
# MAINTENANCE
# ==============================================================================

update-geoip: ## Force update GeoIP database
	@echo "$(YELLOW)Updating GeoIP database...$(NC)"
	@curl -sL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" -o geoip/GeoLite2-City.mmdb
	@echo "$(GREEN)✓ GeoIP updated$(NC)"

rotate-logs: ## Rotate log files
	@./scripts/rotate-logs.sh

backup: ## Backup configuration
	@echo "$(GREEN)Creating backup...$(NC)"
	@tar czf backup-$$(date +%Y%m%d-%H%M%S).tar.gz angie/ modsec/ fail2ban/ .env 2>/dev/null || true
	@echo "$(GREEN)✓ Backup created$(NC)"

# ==============================================================================
# FAIL2BAN
# ==============================================================================

ban-status: ## Show Fail2Ban status
	@docker exec fail2ban fail2ban-client status 2>/dev/null || echo "Fail2Ban not running"

ban-list: ## List banned IPs
	@docker exec fail2ban fail2ban-client banned 2>/dev/null || echo "Fail2Ban not running"

unban: ## Unban IP (usage: make unban IP=1.2.3.4)
	@if [ -z "$(IP)" ]; then echo "Usage: make unban IP=1.2.3.4"; exit 1; fi
	@docker exec fail2ban fail2ban-client unban $(IP)
	@echo "$(GREEN)Unbanned $(IP)$(NC)"

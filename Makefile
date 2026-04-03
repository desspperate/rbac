OS := $(shell uname -s)
DOCKER_COMPOSE := docker compose

.PHONY: all dev prod install configure stop clean help

all: help

# ── Dependencies ───────────────────────────────────────────────────────────────

.installed:
	@echo "Checking dependencies for $(OS)..."
ifeq ($(OS), Darwin)
	@command -v brew >/dev/null 2>&1 || (echo "Installing Homebrew..." && /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")
	@command -v uv >/dev/null 2>&1 || (echo "Installing uv..." && brew install uv)
	@command -v docker >/dev/null 2>&1 || (echo "Checking Docker..." && docker --version)
else ifeq ($(OS), Linux)
	@command -v uv >/dev/null 2>&1 || (echo "Installing uv..." && curl -LsSf https://astral.sh/uv/install.sh | sh)
	@command -v docker >/dev/null 2>&1 || (echo "Please ensure Docker is installed: https://docs.docker.com/engine/install/" && exit 1)
endif
	@uv sync
	@touch .installed
	@echo "Dependencies sync complete"

install: .installed

# ── Configuration ──────────────────────────────────────────────────────────────

configure:
	@bash -c '\
	  ask() { \
	    local key=$$1 dflt=$$2; \
	    read -p "  $$key [$$dflt]: " v; \
	    printf "%s=%s\n" "$$key" "$${v:-$$dflt}"; \
	  }; \
	  echo ""; \
	  echo "   Environment Configuration"; \
	  echo "----------------------------"; \
	  { \
	    echo "# Postgres"; \
	    ask PG_USER "rbac_user"; \
	    ask PG_PASSWORD ""; \
	    ask PG_DB "rbac_database"; \
	    ask PG_DRIVER "postgresql+asyncpg"; \
	    ask PG_HOST "postgres"; \
	    ask PG_PORT "5432"; \
	    echo ""; \
	    echo "# KeyDB"; \
	    ask KDB_PASSWORD ""; \
	    ask KDB_HOST "keydb"; \
	    ask KDB_PORT "6379"; \
	    ask KDB_DB "0"; \
	    echo ""; \
	    echo "# RBAC"; \
	    ask FASTAPI_TITLE "RBAC"; \
	    ask DEBUG "0"; \
	    ask LOGURU_LEVEL "INFO"; \
	  } > .env; \
	  echo ""; \
	  echo ".env file written. You can edit it manually any time."'

.env:
	@$(MAKE) configure

# ── Start ───────────────────────────────────────────────────────────────────

dev: install .env
	$(DOCKER_COMPOSE) --profile dev up -d --build
	@echo "🚀 Dev profile containers are running"

prod: install .env
	$(DOCKER_COMPOSE) --profile prod up -d --build
	@echo "🚀 Prod profile containers are running"

stop:
	$(DOCKER_COMPOSE) --profile dev --profile prod stop
	@echo "🛑 Containers stopped"

clean:
	rm -rf .venv .installed
	find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "🧹 Project cleaned"

help:
	@echo "Usage:"
	@echo "  make install   - Check system tools and sync python deps via uv"
	@echo "  make configure - Create/Overwrite .env file interactively"
	@echo "  make dev       - Run with --profile dev (Docker)"
	@echo "  make prod      - Run with --profile prod (Docker)"
	@echo "  make stop      - Stop all Docker containers"
	@echo "  make clean     - Remove virtualenv and cache files"

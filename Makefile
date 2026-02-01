.PHONY: install lint format fix test build clean help

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies (including dev)"
	@echo "  make lint       - Run linting checks"
	@echo "  make format     - Check code formatting"
	@echo "  make fix        - Auto-fix linting and formatting issues"
	@echo "  make pre-commit - Run all pre-commit hooks"
	@echo "  make test       - Run tests with coverage"
	@echo "  make build      - Build package"
	@echo "  make clean      - Clean build artifacts"

install:
	uv sync --dev
	uv run pre-commit install

lint:
	uv run ruff check .

format:
	uv run ruff format --check .

fix:
	uv run ruff check --fix .
	uv run ruff format .

pre-commit:
	uv run pre-commit run --all-files

test:
	uv run pytest --cov=nuvu_scan --cov-report=term-missing

build:
	uv build

clean:
	rm -rf dist/ build/ *.egg-info/ .coverage coverage.xml .pytest_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

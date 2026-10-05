.PHONY: minimal
minimal: setup

.PHONY: setup
setup:
	uv sync --locked

.PHONY: install-hooks
install-hooks:
	uv run --locked pre-commit install -f --install-hooks

.PHONY: test
test:
	uv run --locked pytest tests

.PHONY: format
format:
	uv run --locked ruff format .

.PHONY: format-check
format-check:
	uv run --locked ruff format --check .

.PHONY: clean
clean:
	find -name '*.pyc' -delete
	find -name '__pycache__' -delete

.PHONY: super-clean
super-clean: clean
	rm -rf .tox
	rm -rf venv

# Claude Code Guidelines

## Rules

- **Never commit or push without explicit user approval.** Always show what changed and wait for confirmation before running `git commit` or `git push`.
- **Never override, suppress, or skip linter/security warnings without explicit user approval.** This includes `nosec`, `noqa`, `type: ignore`, bandit skips in pyproject.toml, and ruff per-file-ignores. If a tool flags something, discuss the finding and proposed suppression before applying it.
- **Run the full CI check locally before proposing a commit:** `ruff check . && ruff format --check . && mypy *.py && bandit -r . -x ./.venv,./tests -ll && pytest tests/ --cov --cov-fail-under=100 -W error::DeprecationWarning`
- **Always update documentation** when changing features, configuration, project structure, or architecture.

## Architecture

- **Model:** `models.py` — dataclasses and enums, no I/O
- **ViewModel:** `alert.py` — severity logic, data aggregation, passes plain dicts to templates. **No HTML in Python.**
- **View:** `templates/*.html` — Jinja2 with inheritance (`base.html`) and macros (`macros.html`). All HTML lives here.
- **Orchestration:** `function_app.py` — timer triggers, message routing, error handling
- **Transport:** `graph_client.py` — MSAL auth + Graph API, retry, timeouts
- **Parsing:** `dmarc_parser.py`, `tlsrpt_parser.py`, `attachment_util.py`
- **Storage:** `storage.py` — Azure Table Storage for report tracking

## Conventions

- Python 3.12, Azure Functions Flex Consumption
- 100% test coverage enforced
- Ruff for linting + formatting, mypy for types, bandit for security, gitleaks for credential scanning
- Templates use macros from `macros.html` for all styled elements (badges, bold, monospace, etc.)
- Environment variables for all configuration — see `docs/configuration.md`

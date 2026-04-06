# Claude Code Guidelines

## Rules

- **Never commit or push without explicit user approval.** Always show what changed and wait for confirmation before running `git commit` or `git push`.
- **Never override, suppress, or skip linter/security warnings without explicit user approval.** This includes `nosec`, `noqa`, `type: ignore`, bandit skips in pyproject.toml, and ruff per-file-ignores. If a tool flags something, discuss the finding and proposed suppression before applying it.
- **Run the full CI check locally before proposing a commit:** `ruff check . && ruff format --check . && mypy *.py --exclude generate_screenshots.py && bandit -r . -x ./.venv,./tests,./generate_screenshots.py -ll && pytest tests/ --cov --cov-fail-under=100 -W error::DeprecationWarning`
- **Always update documentation** when changing features, configuration, project structure, or architecture.
- **Sample images must use generic data only.** When generating screenshots for docs (via `generate_screenshots.py`), use `example.com`, `mail.example.com`, etc. — never real domains like `gieselman.com`.

## Architecture

- **Model:** `models.py` — dataclasses and enums, no I/O
- **ViewModel:** `alert.py` — severity logic, data aggregation, passes plain dicts to templates. **No HTML in Python.**
- **View:** `templates/*.html` — Jinja2 with inheritance (`base.html`) and macros (`macros.html`). All HTML lives here.
- **Delivery:** `delivery.py` — Teams webhook, generic webhook, and email via Graph
- **Orchestration:** `function_app.py` — timer triggers, message routing, deduplication, error handling
- **Transport:** `graph_client.py` — MSAL auth + Graph API, retry, timeouts
- **Parsing:** `dmarc_parser.py`, `tlsrpt_parser.py`, `attachment_util.py`
- **Storage:** `storage.py` — Azure Table Storage for report tracking and deduplication
- **Abuse Reporting:** `abuse.py` — automated abuse reports to hosting providers for confirmed spoofing
- **RDAP Lookup:** `rdap.py` — queries RDAP registries for abuse contact emails by source IP

## Conventions

- Python 3.12, Azure Functions Flex Consumption
- 100% test coverage enforced
- Ruff for linting + formatting, mypy for types, bandit for security, gitleaks for credential scanning
- Templates use macros from `macros.html` for all styled elements (badges, bold, monospace, etc.)
- Environment variables for all configuration — see `docs/configuration.md`

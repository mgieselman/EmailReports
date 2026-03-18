# Contributing to EmailReports

Thanks for your interest in contributing! This project is built for small organizations that need simple, low-cost email security monitoring.

## Getting Started

1. Fork the repo
2. Clone your fork and set up the dev environment:
   ```bash
   python3.12 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   pip install pytest pytest-cov ruff mypy bandit types-requests
   ```
3. Create a feature branch: `git checkout -b my-feature`

## Development Workflow

### Run tests
```bash
pytest tests/ --cov --cov-fail-under=100 -W error::DeprecationWarning
```

### Run linting
```bash
ruff check .
ruff format --check .
mypy *.py
bandit -r . -x ./.venv,./tests -ll
```

### Before submitting a PR

- All tests pass
- Coverage stays at 100% — add tests for new code
- Ruff lint and format pass
- Mypy passes with no errors
- No bandit findings at medium+ severity

## Pull Request Process

1. Open a PR against `main`
2. CI will run lint, tests, and gitleaks automatically
3. All three checks must pass
4. One approval required from a maintainer
5. Squash merge is preferred for clean history

## What Makes a Good PR

- **Small and focused** — one feature or fix per PR
- **Tested** — new code has tests, edge cases covered
- **Documented** — update README/docs if adding config options or changing behavior
- **No secrets** — never commit credentials, connection strings, or webhook URLs
- **No HTML in Python** — all HTML lives in `templates/`. `alert.py` passes plain data to Jinja2 templates. Use macros in `templates/macros.html` for styled elements (badges, bold, monospace, etc.)

## Reporting Issues

- Use GitHub Issues
- Include: what you expected, what happened, steps to reproduce
- For DMARC/TLS-RPT parsing issues, include a sanitized sample report if possible

## Reporting Security Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions. Do not open a public issue for security vulnerabilities.

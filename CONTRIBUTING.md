<!--
SPDX-FileCopyrightText: 2026 AISEC Code Audit Team

SPDX-License-Identifier: CC0-1.0
-->

# Contributing

## Development

1. Clone the repository
2. Install dependencies with `uv sync`
3. Run tests with `uv run pytest tests`

### Linting and Formatting

```bash
$ uv run ruff check
$ uv run ruff format
$ uv run reuse lint
```

### Type Checking

```bash
$ uv run mypy src
```

### Tests

```bash
# Run unit and integration tests
$ uv run pytest
# Include end-to-end tests
$ uv run pytest --e2e
```

## Code Style

- Line length: 120 characters
- Run `uv run ruff format` and `uv run ruff check` before committing
- Type checking is enforced (mypy with strict mode)

## Workflow

- All feature development happens on the `dev` branch
- Small bug fixes can go directly to `main`
- Use feature branches for larger changes

## Pull Requests

Before we can accept a pull request from you, you'll need to sign a Contributor License Agreement (CLA). It is an automated process, and you only need to do it once.
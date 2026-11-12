# SPDX-FileCopyrightText: AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

default:
    @just --list

[private]
lint-mypy platform="linux":
    mypy --pretty --platform {{ platform }}

[private]
lint-ruff-check:
    ruff check

[private]
lint-ruff-format:
    ruff format --check

[private]
lint-reuse:
    reuse lint

# ty defaults to the lower bound of requires-python; the linters
# are supposed to check against the running interpreter instead.
# Only src/ is checked (like mypy); the tests are not fully typed.
[private]
lint-ty platform="linux":
    ty check src --python-platform {{ platform }} --python-version "$(python -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

lint: lint-mypy lint-ty lint-ruff-check lint-ruff-format lint-reuse

fmt:
    ruff check --fix-only
    ruff format

run-tests: run-test-pytest

run-test-pytest:
    python -m pytest -v tests

release increment:
    uv version --bump {{ increment }}

    git commit -a -m "$(uv version)"
    git tag -a -m "$(uv version)" v"$(uv version --short)"
    git push --follow-tags

    gh release create "v$(uv version --short)"

pre-release premode increment="":
    #!/usr/bin/env bash

    increment="{{ increment }}"
    premode="{{ premode }}"

    if [[ "$increment" == "" ]]; then
        uv version --bump "$premode"
    else
        uv version --bump "$premode" --bump "$increment"
    fi

    git commit -a -m "$(uv version)"
    git tag -a -m "$(uv version)" v"$(uv version --short)"
    git push --follow-tags

    gh release create --prerelease "v$(uv version --short)"
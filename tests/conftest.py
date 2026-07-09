# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

# conftest.py

from pathlib import Path
import pytest
from click.testing import CliRunner

CASES_DIR = Path(__file__).parent / "e2e"


def discover_cases():
    cases = []
    for d in CASES_DIR.iterdir():
        if not d.is_dir():
            continue

        input_files = list(d.glob("*.c"))
        input_files += list(d.glob("*.cpp"))
        if not input_files:
            continue

        ref_sarif = d / "ref.sarif"
        if not ref_sarif.exists():
            continue

        exit_code_file = d / "exit_code.txt"

        expected_exit_code = 0
        if exit_code_file.exists():
            expected_exit_code = int(exit_code_file.read_text().strip())

        cases.append(
            {
                "name": d.name,
                "dir": str(d),
                "ref_sarif": str(ref_sarif),
                "expected_exit_code": expected_exit_code,
            }
        )
    return cases


@pytest.fixture
def runner():
    return CliRunner()


def pytest_addoption(parser):
    parser.addoption(
        "--e2e",
        action="store_true",
        default=False,
        help="Run end-to-end tests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: mark test as end-to-end")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--e2e"):
        return
    skip_e2e = pytest.mark.skip(reason="skipped by default; use --e2e to run")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip_e2e)

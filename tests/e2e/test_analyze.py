# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import pytest

from picuscan import main

from conftest import discover_cases

CASES = discover_cases()


@pytest.mark.e2e
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_e2e_cases(runner, case, tmp_path):
    cc = str(tmp_path / "compile-commands.json")
    result = runner.invoke(main, ["compile-commands", "gen", "-o", cc, case["dir"]])
    assert result.exit_code == 0
    out_file = str(tmp_path / "main.sarif")
    result = runner.invoke(main, ["analyze", "-e", "gcc", "-e", "ikos", "-o", out_file, "--run-dir", str(tmp_path), cc])
    assert result.exit_code == case["expected_exit_code"]
    result = runner.invoke(main, ["sarif", "filter", "-l", "warning", "-l", "error", "-o", out_file, out_file])
    assert result.exit_code == 0
    result = runner.invoke(main, ["sarif", "compare", case["ref_sarif"], out_file])
    assert result.exit_code == 0
    assert result.output.count("* No difference") == 3


@pytest.mark.e2e
def test_analyzer_help(runner):
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "Static code analysis" in result.output
    assert "Usage: main analyze" in result.output

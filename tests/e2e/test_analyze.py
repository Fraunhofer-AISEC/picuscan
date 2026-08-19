# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import json
import uuid
from pathlib import Path

import pytest

from picuscan import main

from conftest import discover_cases

CASES = discover_cases()
UNINIT_DIR = str(Path(__file__).parent / "001-basic-uninit")


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


@pytest.mark.e2e
def test_e2e_guid_injected(runner, tmp_path):
    cc = str(tmp_path / "compile-commands.json")
    result = runner.invoke(main, ["compile-commands", "gen", "-o", cc, UNINIT_DIR])
    assert result.exit_code == 0
    out_file = str(tmp_path / "main.sarif")
    result = runner.invoke(main, ["analyze", "-e", "gcc", "-o", out_file, "--run-dir", str(tmp_path), cc])
    assert result.exit_code == 0
    with open(out_file) as f:
        sarif = json.load(f)
    guids: list[str] = []
    for run in sarif["runs"]:
        for result in run["results"]:
            assert "guid" in result
            assert result["guid"] is not None
            parsed = uuid.UUID(result["guid"])
            assert parsed.version == 5
            guids.append(result["guid"])
    assert len(guids) > 0
    assert len(set(guids)) == len(guids)


@pytest.mark.e2e
def test_e2e_guid_stable_across_runs(runner, tmp_path):
    cc = str(tmp_path / "compile-commands.json")
    result = runner.invoke(main, ["compile-commands", "gen", "-o", cc, UNINIT_DIR])
    assert result.exit_code == 0

    out1 = str(tmp_path / "run1.sarif")
    result = runner.invoke(main, ["analyze", "-e", "gcc", "-o", out1, "--run-dir", str(tmp_path / "run1"), cc])
    assert result.exit_code == 0

    out2 = str(tmp_path / "run2.sarif")
    result = runner.invoke(main, ["analyze", "-e", "gcc", "-o", out2, "--run-dir", str(tmp_path / "run2"), cc])
    assert result.exit_code == 0

    with open(out1) as f:
        sarif1 = json.load(f)
    with open(out2) as f:
        sarif2 = json.load(f)

    guids1: set[str] = set()
    guids2: set[str] = set()
    for run in sarif1["runs"]:
        for result in run["results"]:
            guids1.add(result["guid"])
    for run in sarif2["runs"]:
        for result in run["results"]:
            guids2.add(result["guid"])

    assert guids1 == guids2

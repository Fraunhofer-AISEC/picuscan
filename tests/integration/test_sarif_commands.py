# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

from picuscan import main
from picuscan.commands.sarif import load_cwe_names

E2E_DIR = Path(__file__).resolve().parents[1] / "e2e"
UNINIT_SARIF = str(E2E_DIR / "001-basic-uninit" / "ref.sarif")
BUFFER_SARIF = str(E2E_DIR / "002-basic-buffer" / "ref.sarif")


# ---------------------------------------------------------------------------
# load_cwe_names
# ---------------------------------------------------------------------------


def test_load_cwe_names_returns_dict():
    names = load_cwe_names()
    assert isinstance(names, dict)
    assert len(names) > 0


def test_load_cwe_names_known_entries():
    names = load_cwe_names()
    assert names["CWE-457"] == "Use of Uninitialized Variable"
    assert names["CWE-119"] == "Improper Restriction of Operations within the Bounds of a Memory Buffer"
    assert names["CWE-126"] == "Buffer Over-read"


def test_load_cwe_names_missing_entry():
    names = load_cwe_names()
    assert names.get("CWE-999999") is None


def test_load_cwe_names_cached():
    a = load_cwe_names()
    b = load_cwe_names()
    assert a is b


# ---------------------------------------------------------------------------
# sarif info -- CWE categories
# ---------------------------------------------------------------------------


def test_info_shows_cwe_categories(runner):
    result = runner.invoke(main, ["sarif", "info", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "CWE categories" in result.output
    assert "CWE-457" in result.output
    assert "Use of Uninitialized Variable" in result.output
    assert "CWE-119" in result.output
    assert "N/A" in result.output


def test_info_cwe_categories_head_limit(runner):
    result = runner.invoke(main, ["sarif", "info", "-h", "1", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "CWE-457" in result.output
    assert "CWE-119" not in result.output


def test_info_cwe_categories_all(runner):
    result = runner.invoke(main, ["sarif", "info", "-h", "-1", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "CWE-457" in result.output
    assert "CWE-119" in result.output
    assert "N/A" in result.output


def test_info_no_cwe_section_without_taxa(runner, tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool"}},
                "results": [
                    {
                        "ruleId": "rule1",
                        "kind": "open",
                        "level": "warning",
                        "message": {"text": "test"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.c"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = tmp_path / "no_taxa.sarif"
    sarif_path.write_text(json.dumps(sarif))

    result = runner.invoke(main, ["sarif", "info", str(sarif_path)])
    assert result.exit_code == 0
    assert "CWE categories" not in result.output


# ---------------------------------------------------------------------------
# sarif filter --cwe
# ---------------------------------------------------------------------------


def test_filter_by_cwe_id(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Filter based on CWE: ('CWE-457',)" in result.output

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        assert f["taxa"][0]["id"] == "CWE-457"


def test_filter_by_cwe_id_glob(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-4*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        assert f["taxa"][0]["id"] == "CWE-457"


def test_filter_by_cwe_name_glob(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "*Uninitialized*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        assert f["taxa"][0]["id"] == "CWE-457"


def test_filter_by_cwe_name_glob_case_insensitive(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "*uninitialized*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        assert f["taxa"][0]["id"] == "CWE-457"


def test_filter_by_cwe_name_glob_uppercase(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "*UNINITIALIZED*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4


def test_filter_by_multiple_cwe(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-c", "*Buffer*", "-o", str(out), BUFFER_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    cwe_ids = {f["taxa"][0]["id"] for f in findings}
    assert "CWE-457" in cwe_ids
    assert "CWE-119" in cwe_ids
    assert "CWE-126" in cwe_ids
    assert "CWE-788" in cwe_ids


def test_filter_cwe_no_matches(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-999", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 0


def test_filter_cwe_excludes_no_taxa(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        assert f["taxa"][0]["id"] == "CWE-457"


def test_filter_cwe_no_taxa_file(runner, tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool"}},
                "results": [
                    {
                        "ruleId": "rule1",
                        "kind": "open",
                        "level": "warning",
                        "message": {"text": "test"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.c"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    sarif_path = tmp_path / "no_taxa.sarif"
    sarif_path.write_text(json.dumps(sarif))

    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), str(sarif_path)])
    assert result.exit_code == 0

    out_sarif = json.loads(out.read_text())
    findings = [r for run in out_sarif["runs"] for r in run["results"]]
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# sarif filter -- selected findings count
# ---------------------------------------------------------------------------


def test_filter_prints_selected_findings_count(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 4 finding(s)" in result.output


def test_filter_prints_selected_findings_count_zero(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-999", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 0 finding(s)" in result.output


def test_filter_no_cwe_keeps_all(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 6 finding(s)" in result.output

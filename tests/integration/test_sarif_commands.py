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


def test_filter_by_cwe_id(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Filter based on CWE: ('CWE-457',)" in caplog.text

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
# sarif filter --not-cwe
# ---------------------------------------------------------------------------


def test_filter_exclude_by_cwe_id(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Exclude based on CWE: ('CWE-457',)" in caplog.text

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 2
    for f in findings:
        assert f.get("taxa", [{}])[0].get("id") != "CWE-457"


def test_filter_exclude_by_cwe_id_glob(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "CWE-4*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 2
    for f in findings:
        assert f.get("taxa", [{}])[0].get("id") != "CWE-457"


def test_filter_exclude_by_cwe_name_glob(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "*Uninitialized*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 2
    for f in findings:
        assert f.get("taxa", [{}])[0].get("id") != "CWE-457"


def test_filter_exclude_by_cwe_name_glob_case_insensitive(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "*uninitialized*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 2
    for f in findings:
        assert f.get("taxa", [{}])[0].get("id") != "CWE-457"


def test_filter_exclude_by_multiple_cwe(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "CWE-119", "-C", "CWE-457", "-o", str(out), BUFFER_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    cwe_ids = {f.get("taxa", [{}])[0].get("id") for f in findings}
    assert "CWE-119" not in cwe_ids
    assert "CWE-457" not in cwe_ids
    assert "CWE-126" in cwe_ids
    assert "CWE-788" in cwe_ids


def test_filter_exclude_cwe_no_matches(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-C", "CWE-999", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 6


def test_filter_exclude_cwe_keeps_no_taxa(runner, tmp_path):
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
    result = runner.invoke(main, ["sarif", "filter", "-C", "CWE-457", "-o", str(out), str(sarif_path)])
    assert result.exit_code == 0

    out_sarif = json.loads(out.read_text())
    findings = [r for run in out_sarif["runs"] for r in run["results"]]
    assert len(findings) == 1


def test_filter_include_and_exclude_cwe(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "*Buffer*", "-C", "CWE-119", "-o", str(out), BUFFER_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    cwe_ids = {f.get("taxa", [{}])[0].get("id") for f in findings}
    assert "CWE-119" not in cwe_ids
    assert "CWE-126" in cwe_ids
    assert "CWE-788" in cwe_ids


def test_filter_prints_selected_findings_count(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-457", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 4 finding(s)" in caplog.text


def test_filter_prints_selected_findings_count_zero(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-c", "CWE-999", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 0 finding(s)" in caplog.text


def test_filter_no_cwe_keeps_all(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Export 6 finding(s)" in caplog.text


# ---------------------------------------------------------------------------
# sarif search
# ---------------------------------------------------------------------------


def test_search_shows_table(runner):
    result = runner.invoke(main, ["sarif", "search", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "tool" in result.output
    assert "ruleID" in result.output
    assert "level" in result.output
    assert "rank" in result.output
    assert "CWE" in result.output
    assert "location" in result.output
    assert "message" in result.output
    assert "clangsa" in result.output
    assert "core.uninitialized.UndefReturn" in result.output
    assert "main.c" in result.output


def test_search_max_rows(runner):
    result = runner.invoke(main, ["sarif", "search", "--max-rows", "2", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Flawfinder" in result.output
    assert "RATS" in result.output
    assert "clangsa" not in result.output
    assert "Cppcheck" not in result.output
    assert "IKOS" not in result.output
    assert "GCC" not in result.output


def test_search_all_rows_by_default(runner):
    result = runner.invoke(main, ["sarif", "search", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "clangsa" in result.output
    assert "Flawfinder" in result.output
    assert "GCC" in result.output
    assert "Cppcheck" in result.output
    assert "IKOS" in result.output
    assert "RATS" in result.output


def test_search_with_path_filter(runner):
    result = runner.invoke(main, ["sarif", "search", "-p", "*main.c", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "clangsa" in result.output
    assert "main.c" in result.output


def test_search_with_line_filter(runner):
    result = runner.invoke(main, ["sarif", "search", "-L", "2", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Flawfinder" in result.output
    assert "RATS" in result.output
    assert "clangsa" not in result.output


def test_search_with_cwe_filter(runner):
    result = runner.invoke(main, ["sarif", "search", "-c", "CWE-457", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "clangsa" in result.output
    assert "Flawfinder" not in result.output


def test_search_combined_path_line(runner):
    result = runner.invoke(main, ["sarif", "search", "-p", "*main.c", "-L", "2", UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Flawfinder" in result.output
    assert "RATS" in result.output
    assert "clangsa" not in result.output


def test_search_no_findings(runner, tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool"}},
                "results": [],
            }
        ]
    }
    sarif_path = tmp_path / "empty.sarif"
    sarif_path.write_text(json.dumps(sarif))

    result = runner.invoke(main, ["sarif", "search", str(sarif_path)])
    assert result.exit_code == 0
    assert "tool" not in result.output


def test_search_line_invalid_value(runner):
    result = runner.invoke(main, ["sarif", "search", "-L", "abc", UNINIT_SARIF])
    assert result.exit_code == 2
    assert "Invalid value for --line" in result.output


def test_search_json_output(runner):
    result = runner.invoke(main, ["sarif", "search", "--json", UNINIT_SARIF])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 6
    for row in data:
        assert set(row.keys()) == {"tool", "ruleID", "level", "rank", "CWE", "location", "message", "guid"}
    assert any(r["tool"] == "clangsa" for r in data)
    assert all("main.c" in r["location"] for r in data)


def test_search_json_output_with_max_rows(runner):
    result = runner.invoke(main, ["sarif", "search", "--json", "--max-rows", "2", UNINIT_SARIF])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 2


def test_search_json_output_with_filters(runner):
    result = runner.invoke(main, ["sarif", "search", "--json", "-L", "2", UNINIT_SARIF])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 3
    tools = {r["tool"] for r in data}
    assert "Flawfinder" in tools
    assert "RATS" in tools
    assert "GCC" in tools
    assert "clangsa" not in tools


def test_search_json_output_empty(runner, tmp_path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool"}},
                "results": [],
            }
        ]
    }
    sarif_path = tmp_path / "empty.sarif"
    sarif_path.write_text(json.dumps(sarif))

    result = runner.invoke(main, ["sarif", "search", "--json", str(sarif_path)])
    assert result.exit_code == 0
    assert "tool" not in result.output


# ---------------------------------------------------------------------------
# sarif filter --path-filter
# ---------------------------------------------------------------------------


def _result_has_line(result: dict, line: int) -> bool:
    """Check whether a result has any location (code flows, stacks, primary) at the given line."""
    primary = result.get("locations", [{}])[0]
    phys = primary.get("physicalLocation", {})
    if phys.get("region", {}).get("startLine") == line:
        return True
    for flow in result.get("codeFlows", []):
        for tf in flow.get("threadFlows", []):
            for tl in tf.get("locations", []):
                p = tl.get("location", {}).get("physicalLocation", {})
                if p.get("region", {}).get("startLine") == line:
                    return True
    for stack in result.get("stacks", []):
        for frame in stack.get("frames", []):
            p = frame.get("location", {}).get("physicalLocation", {})
            if p.get("region", {}).get("startLine") == line:
                return True
    return False


def test_filter_by_path_glob(runner, tmp_path, caplog):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-p", "*main.c", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0
    assert "Filter based on path: ('*main.c',)" in caplog.text

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 6
    for f in findings:
        uri = f["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.endswith("main.c")


def test_filter_by_path_no_matches(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-p", "*nonexistent*", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 0


def test_filter_by_multiple_paths(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-p", "*main.c", "-p", "*.cpp", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 6


# ---------------------------------------------------------------------------
# sarif filter --line
# ---------------------------------------------------------------------------


def test_filter_by_single_line(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "2", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 3
    for f in findings:
        assert _result_has_line(f, 2)


def test_filter_by_line_range(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "2-3", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 6
    for f in findings:
        line = f["locations"][0]["physicalLocation"]["region"]["startLine"]
        assert 2 <= line <= 3


def test_filter_by_line_range_open_end(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "3-", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 4
    for f in findings:
        line = f["locations"][0]["physicalLocation"]["region"]["startLine"]
        assert line >= 3


def test_filter_by_line_range_open_start(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "-2", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 3
    for f in findings:
        assert _result_has_line(f, 2)


def test_filter_by_line_no_matches(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "999", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 0

    sarif = json.loads(out.read_text())
    findings = [r for run in sarif["runs"] for r in run["results"]]
    assert len(findings) == 0


def test_filter_by_line_invalid_value(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "abc", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 2
    assert "Invalid value for --line" in result.output


def test_filter_by_line_invalid_range(runner, tmp_path):
    out = tmp_path / "out.sarif"
    result = runner.invoke(main, ["sarif", "filter", "-L", "20-10", "-o", str(out), UNINIT_SARIF])
    assert result.exit_code == 2
    assert "Invalid value for --line" in result.output

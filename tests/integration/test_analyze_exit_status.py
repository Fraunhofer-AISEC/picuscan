# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import sys

import pytest

from picuscan import main, sarif
from picuscan.analyzer.tool import Tool
from picuscan.commands import analyze


@pytest.mark.parametrize(
    "tool_names, expected_exit_code, expected_runs",
    [
        pytest.param(["failing"], 1, [], id="complete-failure"),
        pytest.param(["failing", "successful"], 1, ["successful"], id="mixed-results"),
        pytest.param(["successful"], 0, ["successful"], id="all-success"),
        pytest.param(["partial"], 0, ["partial"], id="translation-unit-warning"),
    ],
)
def test_analyze_exit_status(runner, monkeypatch, tmp_path, caplog, tool_names, expected_exit_code, expected_runs):
    # Isolate the controlled analyzers from any installed tools.
    registry = {}
    monkeypatch.setattr("picuscan.analyzer.tool.REGISTRY", registry)
    monkeypatch.setattr(analyze, "REGISTRY", registry)
    monkeypatch.setattr(analyze, "load_tools", lambda: None)

    class Successful(Tool):
        name = "successful"

        def should_run(self):
            return True

        async def run(self):
            return sarif.structure(
                {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": self.name}}, "results": []}]}
            )

    class Failing(Successful):
        name = "failing"

        async def run(self):
            subprocess.run([sys.executable, "-c", "raise SystemExit(42)"], check=True)

    class Partial(Successful):
        name = "partial"

        async def run(self):
            self.failed_sources.add("failed.c")
            return await super().run()

    compile_db = tmp_path / "compile_commands.json"
    compile_db.write_text("[]")
    output = tmp_path / "results.sarif"
    args = ["analyze", "--no-sarif-transform", "--output", str(output), "--run-dir", str(tmp_path / "run")]
    for name in tool_names:
        args.extend(["--tool", name])
    args.append(str(compile_db))

    result = runner.invoke(main, args)

    assert result.exit_code == expected_exit_code, result.output
    report = json.loads(output.read_text())
    assert sorted(run["tool"]["driver"]["name"] for run in report["runs"]) == expected_runs
    if "failing" in tool_names:
        assert "exit status 42" in caplog.text
    if "partial" in tool_names:
        assert "partial failed to analyze 1 translation unit(s): failed.c" in caplog.text

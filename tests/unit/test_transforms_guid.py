# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import uuid

from picuscan.analyzer.transforms import inject_guid
from picuscan.sarif import dumps, loads, unstructure
from picuscan.sarif.models import (
    CodeFlow,
    Log,
    Message,
    Result,
    Run,
    ThreadFlow,
    ThreadFlowLocation,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    Tool,
    ToolComponent,
    Version,
)


def _make_log(*results: Result, tool_name: str = "test") -> Log:
    return Log(
        version=Version.V2_1_0,
        runs=(
            Run(
                tool=Tool(driver=ToolComponent(name=tool_name)),
                results=frozenset(results),
            ),
        ),
    )


def _result(**kw) -> Result:
    defaults = dict(message=Message(text="test finding"))
    defaults.update(kw)
    return Result(**defaults)


def test_inject_guid_populates_missing():
    r = _result()
    log = _make_log(r)
    out = inject_guid()(log, None)
    (transformed,) = out.runs[0].results
    assert transformed.guid is not None


def test_inject_guid_preserves_existing():
    existing = "11111111-2222-3333-4444-555555555555"
    r = _result(guid=existing)
    log = _make_log(r)
    out = inject_guid()(log, None)
    (transformed,) = out.runs[0].results
    assert transformed.guid == existing


def test_inject_guid_format():
    r = _result()
    log = _make_log(r)
    out = inject_guid()(log, None)
    (transformed,) = out.runs[0].results
    parsed = uuid.UUID(transformed.guid)
    assert parsed.version == 5


def test_inject_guid_distinct():
    r1 = _result(ruleId="A")
    r2 = _result(ruleId="B")
    log = _make_log(r1, r2)
    out = inject_guid()(log, None)
    guids = {r.guid for r in out.runs[0].results}
    assert len(guids) == 2
    assert None not in guids


def test_inject_guid_deterministic():
    r1 = _result(ruleId="RULE001")
    r2 = _result(ruleId="RULE001")
    out1 = inject_guid()(_make_log(r1), None)
    out2 = inject_guid()(_make_log(r2), None)
    g1 = next(iter(out1.runs[0].results)).guid
    g2 = next(iter(out2.runs[0].results)).guid
    assert g1 == g2


def test_inject_guid_stable_across_runs():
    r = _result(ruleId="RULE001")
    log1 = _make_log(r)
    out1 = inject_guid()(log1, None)
    g1 = next(iter(out1.runs[0].results)).guid

    serialized = dumps(out1)
    reloaded = loads(serialized)
    out2 = inject_guid()(reloaded, None)
    g2 = next(iter(out2.runs[0].results)).guid

    assert g1 == g2


def test_inject_guid_differs_by_tool():
    r = _result(ruleId="RULE001")
    out1 = inject_guid()(_make_log(r, tool_name="toolA"), None)
    out2 = inject_guid()(_make_log(r, tool_name="toolB"), None)
    g1 = next(iter(out1.runs[0].results)).guid
    g2 = next(iter(out2.runs[0].results)).guid
    assert g1 != g2


def test_inject_guid_differs_by_message():
    r1 = _result(message=Message(text="finding A"))
    r2 = _result(message=Message(text="finding B"))
    log = _make_log(r1, r2)
    out = inject_guid()(log, None)
    guids = {r.guid for r in out.runs[0].results}
    assert len(guids) == 2


def test_inject_guid_differs_by_location():
    loc_a = Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri="src/a.c"),
            region=Region(startLine=10, startColumn=3),
        )
    )
    loc_b = Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri="src/a.c"),
            region=Region(startLine=20, startColumn=3),
        )
    )
    r1 = _result(ruleId="RULE001", locations=(loc_a,))
    r2 = _result(ruleId="RULE001", locations=(loc_b,))
    log = _make_log(r1, r2)
    out = inject_guid()(log, None)
    guids = {r.guid for r in out.runs[0].results}
    assert len(guids) == 2


def test_inject_guid_differs_by_steps():
    flow = CodeFlow(
        threadFlows=(
            ThreadFlow(
                locations=(
                    ThreadFlowLocation(
                        location=Location(
                            physicalLocation=PhysicalLocation(
                                artifactLocation=ArtifactLocation(uri="src/a.c"),
                                region=Region(startLine=5),
                            )
                        )
                    ),
                )
            ),
        )
    )
    r1 = _result(ruleId="RULE001", codeFlows=())
    r2 = _result(ruleId="RULE001", codeFlows=(flow,))
    log = _make_log(r1, r2)
    out = inject_guid()(log, None)
    guids = {r.guid for r in out.runs[0].results}
    assert len(guids) == 2


def test_inject_guid_serialized_when_set():
    r = _result(guid="11111111-2222-3333-4444-555555555555")
    u = unstructure(r)
    assert u["guid"] == "11111111-2222-3333-4444-555555555555"


def test_inject_guid_omitted_when_none():
    r = _result()
    u = unstructure(r)
    assert "guid" not in u

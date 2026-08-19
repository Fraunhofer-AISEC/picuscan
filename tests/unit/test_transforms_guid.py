# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import uuid

from picuscan.analyzer.transforms import inject_guid
from picuscan.sarif import unstructure
from picuscan.sarif.models import (
    Log,
    Message,
    Result,
    Run,
    Tool,
    ToolComponent,
    Version,
)


def _make_log(*results: Result) -> Log:
    return Log(
        version=Version.V2_1_0,
        runs=(
            Run(
                tool=Tool(driver=ToolComponent(name="test")),
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
    assert parsed.version == 4


def test_inject_guid_distinct():
    r1 = _result(ruleId="A")
    r2 = _result(ruleId="B")
    log = _make_log(r1, r2)
    out = inject_guid()(log, None)
    guids = {r.guid for r in out.runs[0].results}
    assert len(guids) == 2
    assert None not in guids


def test_inject_guid_serialized_when_set():
    r = _result(guid="11111111-2222-3333-4444-555555555555")
    u = unstructure(r)
    assert u["guid"] == "11111111-2222-3333-4444-555555555555"


def test_inject_guid_omitted_when_none():
    r = _result()
    u = unstructure(r)
    assert "guid" not in u

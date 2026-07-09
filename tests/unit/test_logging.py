# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Iterable, Mapping

import pytest
from pytest import LogCaptureFixture

from picuscan.logging import Tracer, get_logger

logger = get_logger(__name__)
logger.setLevel("DEBUG")
logger.propagate = True

tracer = Tracer(logger)


@tracer.trace
def foo(x: int = 120, y: int = 121):
    return x + y


@pytest.mark.parametrize(
    ("args", "kwds", "expect"),
    [
        ([], {}, "foo() = 241"),
        ([0], {}, "foo(0) = 121"),
        ([1, 2], {}, "foo(1, 2) = 3"),
        ([], {"x": 0}, "foo(x=0)"),
        ([], {"y": 0}, "foo(y=0)"),
        ([], {"y": 1, "x": 2}, "foo(y=1, x=2) = 3"),
        ([1], {"y": 2}, "foo(1, y=2) = 3"),
    ],
)
def test_tracer(args: Iterable[Any], kwds: Mapping[str, Any], expect: str, caplog: LogCaptureFixture):
    assert isinstance(foo(*args, **kwds), int)
    assert expect in caplog.text


@tracer.trace_async
async def bar(x: int = 120, y: int = 121):
    return x + y


@pytest.mark.parametrize(
    ("args", "kwds", "expect"),
    [
        ([], {}, "bar() = 241"),
        ([0], {}, "bar(0) = 121"),
        ([1, 2], {}, "bar(1, 2) = 3"),
        ([], {"x": 0}, "bar(x=0)"),
        ([], {"y": 0}, "bar(y=0)"),
        ([], {"y": 1, "x": 2}, "bar(y=1, x=2) = 3"),
        ([1], {"y": 2}, "bar(1, y=2) = 3"),
    ],
)
@pytest.mark.asyncio
async def test_tracer_async(args: Iterable[Any], kwds: Mapping[str, Any], expect: str, caplog: LogCaptureFixture):
    value = await bar(*args, **kwds)
    assert isinstance(value, int)
    assert expect in caplog.text

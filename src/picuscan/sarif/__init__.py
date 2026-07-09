# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import IO, Any, AnyStr

from picuscan.sarif.converter import get_converter
from picuscan.sarif.models import *  # noqa: F403

_converter = get_converter()


def load(fp: IO[Any]) -> Log:  # noqa: F405
    obj = json.load(fp)
    return structure(obj)


def loads(s: AnyStr) -> Log:  # noqa: F405
    obj = json.loads(s)
    return structure(obj)


def structure(obj: Any) -> Log:  # noqa: F405
    return _converter.structure(obj, Log)  # noqa: F405


def dump(log: Log, fp: IO[Any], indent: int = 2) -> None:  # noqa: F405
    json.dump(unstructure(log), fp, indent=indent)


def dumps(log: Log, indent: int = 2) -> str:  # noqa: F405
    return json.dumps(unstructure(log), indent=indent)


def unstructure(log: Log) -> Any:  # noqa: F405
    return _converter.unstructure(log)

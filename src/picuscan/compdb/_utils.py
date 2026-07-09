# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import typing as t
from pathlib import Path

import attrs

from ._converter import make_converter
from ._types import CompilationDB


def structure(o: object, *, path: Path | None = None) -> CompilationDB:
    db = _converter.structure(o, CompilationDB)
    if path is None:
        return db
    return attrs.evolve(db, path=path)


def unstructure(db: CompilationDB) -> object:
    return _converter.unstructure(db)


def load(input: Path | t.IO[t.Any]) -> CompilationDB:
    if isinstance(input, Path):
        with open(input, "rb") as f:
            o = json.load(f)
        path = input
    else:
        o = json.load(input)
        try:
            path = Path(input.name)
        except AttributeError:
            path = None
    return structure(o, path=path)


def dump(db: CompilationDB, fp: t.IO[str]) -> None:
    o = unstructure(db)
    json.dump(o, fp, indent=2)


_converter = make_converter()

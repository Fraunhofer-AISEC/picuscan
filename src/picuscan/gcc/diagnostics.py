# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
import re
from pathlib import Path

import attrs


@attrs.frozen
class Diagnostic:
    kind: DiagnosticKind
    location: DiagnosticLocation
    msg: str

    @property
    def is_error(self) -> bool:
        return self.kind == DiagnosticKind.ERROR

    @property
    def is_warning(self) -> bool:
        return self.kind == DiagnosticKind.WARNING


class DiagnosticKind(enum.Enum):
    ERROR = "error"
    WARNING = "warning"


@attrs.frozen
class DiagnosticLocation:
    file: Path
    line: int
    col: int


def parse_output(s: str) -> list[Diagnostic]:
    diagnostics = (_parse_diagnostic(line) for line in s.splitlines())
    return [d for d in diagnostics if d]


_MESSAGE_PATTERN = re.compile(r"(.+):(\d+):(\d+): (error|warning): (.+)")


def _parse_diagnostic(s: str) -> Diagnostic | None:
    if match := re.match(_MESSAGE_PATTERN, s):
        file, line, col, kind, msg = match.groups()
        kind = DiagnosticKind(kind)
        location = DiagnosticLocation(Path(file), int(line), int(col))
        return Diagnostic(kind, location, msg)
    return None

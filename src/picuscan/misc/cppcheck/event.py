# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import attrs


@attrs.frozen
class Checking:
    """`path` is getting checked by Cppcheck."""

    path: Path


@attrs.frozen
class Checked:
    """A file has been checked."""

    count: int
    """The number of files that have been checked so far."""
    total: int
    """The total number of files."""
    percentwise: int
    """The percentage of files that have been checked so far."""


Event = Checking | Checked

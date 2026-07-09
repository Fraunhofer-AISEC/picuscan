# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import typing as t


def is_binary(file: t.IO[t.Any]) -> t.TypeGuard[t.IO[bytes]]:
    try:
        return "b" in file.mode
    except AttributeError:
        # StringIO & BytesIO don't have this attribute. Resort to
        # isinstance checks.
        return not isinstance(file, io.TextIOBase)


def is_text(file: t.IO[t.Any]) -> t.TypeGuard[t.IO[str]]:
    return not is_binary(file)

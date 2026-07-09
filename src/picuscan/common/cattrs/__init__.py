# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from cattrs.preconf import json as _json

from ._configure import configure_converter

__all__ = ("configure_converter", "make_json_converter")


def make_json_converter() -> _json.JsonConverter:
    c = _json.make_converter()
    configure_converter(c)
    return c

# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
import typing as t

C_SOURCE_SUFFIXES = {".c"}
C_HEADER_SUFFIXES = {".h"}
C_SUFFIXES = C_SOURCE_SUFFIXES | C_HEADER_SUFFIXES

CXX_SOURCE_SUFFIXES = {".cpp", ".cxx", ".cc"}
CXX_HEADER_SUFFIXES = {".hpp", ".hxx", ".hh"}
CXX_SUFFIXES = CXX_SOURCE_SUFFIXES | CXX_HEADER_SUFFIXES

C_CXX_SOURCE_SUFFIXES = C_SOURCE_SUFFIXES | CXX_SOURCE_SUFFIXES
C_CXX_HEADER_SUFFIXES = C_HEADER_SUFFIXES | CXX_HEADER_SUFFIXES
C_CXX_SUFFIXES = C_SUFFIXES | CXX_SUFFIXES


class Language(enum.IntEnum):
    C = enum.auto()
    CXX = enum.auto()


def _get_languages() -> dict[str, Language]:
    return {**{s: Language.C for s in C_SUFFIXES}, **{s: Language.CXX for s in CXX_SUFFIXES}}


LANGUAGES: t.Mapping[str, Language] = _get_languages()

# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This module models the XML output of Cppcheck for type safety."""

from __future__ import annotations

import typing as t

from typing_extensions import NotRequired, TypedDict


class Output(TypedDict):
    results: Results


_ResultsAttributes = TypedDict("_ResultsAttributes", {"@version": t.Literal["2"]})


class Results(_ResultsAttributes):
    cppcheck: Cppcheck
    errors: Errors | None


Cppcheck = TypedDict("Cppcheck", {"@version": str})


class Errors(TypedDict):
    error: Error | list[Error]


Severity = t.Literal["", "error", "warning", "style", "performance", "portability", "information", "debug"]

_ErrorAttributes = TypedDict(
    "_ErrorAttributes",
    {
        "@id": str,
        "@severity": Severity,
        "@msg": str,
        "@verbose": str,
        "@cwe": NotRequired[str],
        "@hash": NotRequired[str],
        "@inconclusive": NotRequired[t.Literal["true"]],
    },
)


class Error(_ErrorAttributes):
    location: NotRequired[Location | list[Location]]


Location = TypedDict(
    "Location", {"@file0": NotRequired[str], "@file": str, "@line": str, "@column": str, "@info": NotRequired[str]}
)

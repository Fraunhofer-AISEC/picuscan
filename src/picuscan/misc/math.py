# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations


def clamp(n: int, min: int, max: int) -> int:
    if min > max:
        raise ValueError("min should be less than max.")
    if n < min:
        return min
    if n > max:
        return max
    return n

# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations


def fixed_width_desc(n: int = 15) -> str:
    return f"{{desc:{n}.{n}}}{{percentage:3.0f}}%|{{bar}}{{r_bar}}"

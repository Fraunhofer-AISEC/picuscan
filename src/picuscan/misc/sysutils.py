# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os


def cpu_count() -> int:
    """Return (approximately) the number of CPUs that are available to us."""
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        # os.sched_getaffinity is not available on all platforms.
        n = os.cpu_count()
        if n is None:
            return 1
        return n

# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import attrs
from tqdm import tqdm

from .event import Checked, Checking, Event


@attrs.define
class update_tqdm[T]:
    """This is an event handler that automatically updates a progress
    bar as Cppcheck processes files."""

    instance: tqdm[T]
    _last: int = attrs.field(default=0, init=False)

    def __call__(self, event: Event) -> None:
        match event:
            case Checked(_, _, percentwise):
                diff = percentwise - self._last
                self._last = percentwise
                self.instance.update(diff)
            case Checking(path):
                self.instance.set_description(f"{path.name}")

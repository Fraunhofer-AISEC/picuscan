# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from . import ffi

class ValueRef(ffi.ObjectRef):
    @property
    def is_function(self) -> bool: ...
    @property
    def name(self) -> str: ...
    @name.setter
    def name(self, val: str) -> None: ...

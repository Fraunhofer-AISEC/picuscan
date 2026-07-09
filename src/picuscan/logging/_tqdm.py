# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from logging import LogRecord, StreamHandler

from tqdm import tqdm

# StreamHandler doesn't inherit from t.Generic, so we do this to prevent
# a runtime error while preserving type safety.
if t.TYPE_CHECKING:

    class _StreamHandler(StreamHandler[t.TextIO]):
        pass
else:

    class _StreamHandler(StreamHandler):
        pass


class TqdmStreamHandler(_StreamHandler):
    """A stream handler that coordinates its write operations with the
    `tqdm` library. Without this, progress bars might not look as expected."""

    def emit(self, record: LogRecord) -> None:
        with tqdm.external_write_mode(file=self.stream):
            return super().emit(record)

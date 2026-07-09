# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import typing as t

import click


class _Style(t.TypedDict, total=False):
    fg: str
    bold: bool


class ANSIFormatter(logging.Formatter):
    """Use pretty colors for the logger output."""

    STYLES = {
        logging.CRITICAL: _Style(fg="red", bold=True),
        logging.ERROR: _Style(fg="red", bold=True),
        logging.WARNING: _Style(fg="yellow", bold=True),
        logging.DEBUG: _Style(fg="cyan"),
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        try:
            return click.style(msg, **self.STYLES[record.levelno])
        except KeyError:
            return msg

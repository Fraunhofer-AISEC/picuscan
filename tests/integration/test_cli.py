# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import click

import picuscan


def test_help():
    with click.Context(picuscan.main) as ctx:
        help = [s.strip() for s in picuscan.main.get_help(ctx).splitlines()]
        assert isinstance(picuscan.main, click.Group)
        cmds = picuscan.main.list_commands(ctx)
        assert all(any(s.startswith(cmd) for s in help) for cmd in cmds)

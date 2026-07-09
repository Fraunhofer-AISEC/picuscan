# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from cattrs.converters import GenConverter
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override
from cattrs.preconf.json import make_converter

from picuscan.sarif.models import Log


def get_converter() -> GenConverter:
    c = make_converter(omit_if_default=True)

    # `$schema` is not a valid variable name in Python, so we map it to `schema`.
    c.register_structure_hook(
        Log,
        make_dict_structure_fn(
            Log,
            c,
            properties=override(omit_if_default=True),
            schema=override(omit_if_default=True, rename="$schema"),
        ),
    )
    c.register_unstructure_hook(
        Log,
        make_dict_unstructure_fn(
            Log,
            c,
            properties=override(omit_if_default=True),
            schema=override(omit_if_default=True, rename="$schema"),
        ),
    )

    return c

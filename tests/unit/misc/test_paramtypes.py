# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

import enum

import click
import pytest

from picuscan.misc import paramtypes


class Enum(enum.Enum):
    FOO = "a"
    BAR = "b"


class IntEnum(enum.IntEnum):
    FOO = 1
    BAR = 2


@pytest.mark.parametrize(
    ("param", "value", "expect"),
    [
        (paramtypes.Enum(Enum), "foo", Enum.FOO),
        (paramtypes.Enum(Enum), "FOO", Enum.FOO),
        (paramtypes.Enum(Enum), "a", Enum.FOO),
        (paramtypes.Enum(Enum), "bar", Enum.BAR),
        (paramtypes.Enum(Enum), "BAR", Enum.BAR),
        (paramtypes.Enum(Enum), "b", Enum.BAR),
        (paramtypes.Enum(IntEnum), "1", IntEnum.FOO),
        (paramtypes.Enum(IntEnum), "2", IntEnum.BAR),
        (paramtypes.Sequence(), "", ()),
        (paramtypes.Sequence(), "foo", ("foo",)),
        (paramtypes.Sequence(), "foo,bar", ("foo", "bar")),
        (paramtypes.Sequence(sep=";"), "foo;bar", ("foo", "bar")),
        (paramtypes.Sequence(), ["foo", "bar"], ("foo", "bar")),
        (paramtypes.Sequence(click.INT), "1,2,3", (1, 2, 3)),
        (paramtypes.Sequence(click.INT), ["1", "2", "3"], (1, 2, 3)),
    ],
)
def test_param_type(param: click.ParamType, value: object, expect: object):
    assert param.convert(value, None, None) == expect


@pytest.mark.parametrize(
    ("param", "value"),
    [
        (paramtypes.Enum(Enum), "foobar"),
        (paramtypes.Enum(IntEnum), "foobar"),
        (paramtypes.Enum(IntEnum), "3"),
        (paramtypes.Sequence(click.INT), "foo,bar"),
    ],
)
def test_param_type_fail(param: click.ParamType, value: object):
    with pytest.raises(click.BadParameter):
        param.convert(value, None, None)

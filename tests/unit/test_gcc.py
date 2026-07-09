# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from picuscan import gcc


@pytest.mark.parametrize(
    ["args", "expected"],
    [
        ([], (gcc.Options(), [])),
        (["foo.c"], (gcc.Options(), ["foo.c"])),
        (["foo.c", "bar.c"], (gcc.Options(), ["foo.c", "bar.c"])),
        (["-c"], (gcc.Options(link=False), [])),
        (["-S"], (gcc.Options(assemble=False), [])),
        (["-o", "foo.c"], (gcc.Options(output=Path("foo.c")), [])),
        (["-ansi"], (gcc.Options(ansi=True), [])),
        (["-std=c99"], (gcc.Options(standard="c99"), [])),
        (["-g"], (gcc.Options(debug=True), [])),
        (["-O"], (gcc.Options(optimize=True), [])),
        (["-O0"], (gcc.Options(optimize="0"), [])),
        (["-Os"], (gcc.Options(optimize="s"), [])),
        (["-Ofast"], (gcc.Options(optimize="fast"), [])),
        (["-DFOO"], (gcc.Options(preprocessor_defines=["FOO"]), [])),
        (["-DFOO=1"], (gcc.Options(preprocessor_defines=["FOO=1"]), [])),
        (["-DFOO", "-D", "BAR"], (gcc.Options(preprocessor_defines=["FOO", "BAR"]), [])),
        (["-UFOO"], (gcc.Options(preprocessor_undefines=["FOO"]), [])),
        (["-I/usr/include"], (gcc.Options(include_dirs=[Path("/usr/include")]), [])),
    ],
)
def test_parse(args, expected):
    value = gcc.parse(args)
    assert value == expected


@pytest.mark.parametrize(
    "args",
    [["-o"], ["-x"], ["-std"], ["-D"], ["-U"], ["-I"]],
)
def test_parse_fail(args):
    with pytest.raises(gcc.ParseError):
        gcc.parse(args)


@pytest.mark.parametrize(
    "args",
    [
        ["-c", "-o", "foo.c.o", "-std=c99", "-O3", "-D_FORTIFY_SOURCE=1", "foo.c"],
    ],
)
def test_options_args(args):
    expected, _ = gcc.parse(args)
    options, _ = gcc.parse(list(expected.args))
    assert expected == options

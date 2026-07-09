# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from time import sleep

import pytest

from picuscan.common.file import find, glob, modify, rewrite


@pytest.fixture
def root(tmp_path: Path):
    a = tmp_path / "a"
    b = a / "b"
    c = b / "c"

    d = tmp_path / "d"

    c.mkdir(parents=True)
    d.mkdir()

    files = [p / "foo" for p in (tmp_path, c)] + [d / "bar"]
    for p in files:
        p.touch()

    return tmp_path


@pytest.mark.parametrize("path", [Path("foo"), Path("d/bar")])
def test_find(path: Path, root: Path):
    paths = tuple(find(path, dirs=root))
    (p,) = paths
    assert p == root / path


def test_multiple_dirs(root: Path):
    paths = tuple(find(Path("foo"), dirs=[root, root / "a" / "b" / "c"]))
    assert len(paths) == 2
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths


@pytest.mark.parametrize("path", [Path("FOO"), Path("D/BAR")])
def test_find_case_insensitive(path: Path, root: Path):
    paths = tuple(find(path, dirs=root, case_sensitive=False))
    (p,) = paths
    assert p.name.casefold() == path.name.casefold()


def test_find_recursive(root: Path):
    paths = tuple(find(Path("foo"), dirs=root, recursive=True))
    assert len(paths) == 2
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths


@pytest.mark.parametrize("path", [Path("a/b/c/foo"), Path("b/c/foo"), Path("c/foo")])
def test_find_recursive_subdirs(path: Path, root: Path):
    paths = tuple(find(path, dirs=root, recursive=True))
    (p,) = paths
    assert p == root / "a" / "b" / "c" / "foo"


def test_find_recursive_case_insensitive(root: Path):
    paths = tuple(find(Path("FOO"), dirs=root, recursive=True, case_sensitive=False))
    assert len(paths) == 2
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths


@pytest.mark.parametrize("path", [Path("A/B/C/FOO"), Path("B/C/FOO"), Path("C/FOO")])
def test_find_recursive_case_insensitive_subdirs(path: Path, root: Path):
    paths = tuple(find(path, dirs=root, recursive=True, case_sensitive=False))
    (p,) = paths
    assert p == root / "a" / "b" / "c" / "foo"


def test_glob(root: Path):
    paths = tuple(glob(root, "*o"))
    assert len(paths) == 2
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths


def test_glob_multiple(root: Path):
    paths = tuple(glob(root, ["*/foo", "*/bar"]))
    assert len(paths) == 3
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths
    assert root / "d" / "bar" in paths


def test_glob_exclude(root: Path):
    paths = tuple(glob(root, exclude="*o"))
    assert root / "foo" not in paths
    assert root / "a" / "b" / "c" / "foo" not in paths


def test_glob_exclude_multiple(root: Path):
    paths = tuple(glob(root, exclude=["*/foo", "*/bar"]))
    assert root / "foo" not in paths
    assert root / "a" / "b" / "c" / "foo" not in paths
    assert root / "d" / "bar" not in paths


def test_glob_files(root: Path):
    paths = tuple(glob(root, dir_ok=False))
    assert len(paths) == 3
    assert root / "foo" in paths
    assert root / "a" / "b" / "c" / "foo" in paths
    assert root / "d" / "bar" in paths


def test_glob_dirs(root: Path):
    paths = tuple(glob(root, file_ok=False))
    assert len(paths) == 4
    assert root / "a" in paths
    assert root / "a" / "b" in paths
    assert root / "a" / "b" / "c" in paths
    assert root / "d" in paths


def test_glob_complex(root: Path):
    (p,) = glob(root, "*/foo", "*/c/*")
    assert p == root / "foo"


LINES = ("foo", "bar", "foobar")


@pytest.fixture
def foo(tmp_path: Path):
    file = tmp_path / "foo.txt"
    file.write_text("\n".join([*LINES, ""]))
    sleep(0.001)  # Without this, `st_mtime` doesn't change  even when modified.
    return file


def test_modify(foo: Path):
    stat = foo.stat()
    with modify(foo) as m:
        i = -1
        for s, i in zip(m, range(len(LINES))):
            assert s == f"{LINES[i]}\n"
        assert i == len(LINES) - 1
    assert stat == foo.stat()


def test_modify_replace(foo: Path):
    stat = foo.stat()
    with modify(foo) as m:
        i = 0
        for s in m:
            m.replace(s.capitalize())
            i += 1
        assert i == len(LINES)
    assert foo.read_text() == "\n".join([*(s.capitalize() for s in LINES), ""])
    current_stat = foo.stat()
    assert current_stat != stat
    assert current_stat.st_mode == stat.st_mode


def test_modify_replace_last(foo: Path):
    stat = foo.stat()
    with modify(foo) as m:
        i = 0
        for s in m:
            if s.rstrip() == LINES[-1]:
                m.replace(s.capitalize())
            i += 1
        assert i == len(LINES)
    assert foo.read_text() == "\n".join([*LINES[:-1], LINES[-1].capitalize(), ""])
    current_stat = foo.stat()
    assert current_stat != stat
    assert current_stat.st_mode == stat.st_mode


def test_modify_exception(foo: Path):
    stat = foo.stat()
    with pytest.raises(RuntimeError):
        with modify(foo) as m:
            for s in m:
                m.replace(s.capitalize())
            raise RuntimeError
    assert foo.read_text() == "\n".join([*LINES, ""])
    assert stat == foo.stat()


def test_rewrite_cross_mount(tmp_path: Path):
    foo = Path("/dev/foo")
    try:
        foo.touch()
    except OSError:
        pytest.skip()
    symlink = tmp_path / "foo"
    symlink.symlink_to(foo)
    try:
        with rewrite(symlink):
            pass
    finally:
        foo.unlink(missing_ok=True)

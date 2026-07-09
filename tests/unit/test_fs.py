# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from picuscan import fs


def test_temp_dir():
    with fs.temp_dir() as p:
        assert p.is_dir()
    assert not p.exists()


def test_temp_file():
    with fs.temp_file() as file:
        assert file.path.is_file()
    assert not file.path.exists()


def test_temp_file_write():
    with fs.temp_file() as file:
        file.write(b"foo")
        file.flush()
        assert file.path.read_bytes() == b"foo"


def test_temp_file_no_delete(tmp_path: Path):
    with fs.temp_file(dir=tmp_path, delete=False) as file:
        assert file.path.is_file()
    assert file.path.exists()


def test_lazyfile(tmp_path: Path):
    path = tmp_path / "foo"
    with fs.lazyfile(path, "w") as _:
        pass
    assert not path.exists()


def test_lazyfile_write(tmp_path: Path):
    path = tmp_path / "foo"
    with fs.lazyfile(path, "w") as file:
        assert not path.exists()
        file.write("foo")
    assert path.exists()
    assert path.read_text() == "foo"

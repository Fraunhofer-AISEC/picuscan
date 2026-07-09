# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This module includes lists of standard C/C++ headers."""

c_headers = frozenset(
    [
        "assert.h",
        "ctype.h",
        "errno.h",
        "float.h",
        "limits.h",
        "locale.h",
        "math.h",
        "setjmp.h",
        "signal.h",
        "stdarg.h",
        "stddef.h",
        "stdio.h",
        "stdlib.h",
        "string.h",
        "time.h",
    ]
)

c_95_headers = frozenset(["iso646.h", "wchar.h", "wctype.h"])
c_99_headers = frozenset(["complex.h", "fenv.h", "inttypes.h", "stdbool.h", "stdint.h", "tgmath.h"])
c_11_headers = frozenset(["stdalign.h", "stdatomic.h", "stdnoreturn.h", "threads.h", "uchar.h"])
c_23_headers = frozenset(["stdbit.h", "stdckdint.h"])

all_c_headers = c_headers | c_95_headers | c_99_headers | c_11_headers | c_23_headers

cxx_headers = frozenset(
    [
        "bitset",
        "csetjmp",
        "csignal",
        "cstdarg",
        "cstddef",
        "cstdlib",
        "ctime",
        "functional",
        "typeinfo",
        "utility",
        "memory",
        "new",
        "cfloat",
        "climits",
        "limits",
        "cassert",
        "cerrno",
        "exception",
        "stdexcept",
        "cctype",
        "cstring",
        "cwchar",
        "cwctype",
        "string",
        "deque",
        "list",
        "map",
        "queue",
        "set",
        "stack",
        "vector",
        "iterator",
        "algorithm",
        "cmath",
        "complex",
        "numeric",
        "valarray",
        "clocale",
        "locale",
        "cstdio",
        "fstream",
        "iomanip",
        "ios",
        "iosfwd",
        "iostream",
        "istream",
        "ostream",
        "sstream",
        "streambuf",
        "strstream",
    ]
)

cxx_11_headers = frozenset(
    [
        "chrono",
        "initializer_list",
        "tuple",
        "type_traits",
        "typeindex",
        "scoped_allocator",
        "cinttypes",
        "cstdint",
        "system_error",
        "cuchar",
        "array",
        "forward_list",
        "unordered_map",
        "unordered_set",
        "cfenv",
        "random",
        "ratio",
        "codecvt",
        "regex",
        "atomic",
        "condition_variable",
        "future",
        "mutex",
        "thread",
    ]
)

cxx_14_headers = frozenset(["shared_mutex"])
cxx_17_headers = frozenset(
    ["any", "optional", "variant", "memory_resource", "charconv", "string_view", "execution", "filesystem"]
)

cxx_20_headers = frozenset(
    [
        "concepts",
        "coroutine",
        "compare",
        "source_location",
        "version",
        "format",
        "span",
        "ranges",
        "bit",
        "numbers",
        "syncstream",
        "barrier",
        "latch",
        "semaphore",
        "stop_token",
    ]
)

cxx_23_headers = frozenset(
    ["expected", "stdfloat", "stacktrace", "flat_map", "flat_set", "mdspan", "generator", "print", "spanstream"]
)

all_cxx_headers = cxx_headers | cxx_11_headers | cxx_14_headers | cxx_17_headers | cxx_20_headers | cxx_23_headers

all_headers = all_c_headers | all_cxx_headers

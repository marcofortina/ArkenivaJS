# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Verify that the Linux Kafka addon owns its private zlib implementation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


REQUIRED = frozenset({
    "z_deflate", "z_deflateEnd", "z_deflateInit2_",
    "z_inflate", "z_inflateEnd", "z_inflateInit2_", "z_inflateReset2",
    "z_zlibVersion",
})
# Exact linked symbol aliases from upstream zlib 1.4 zconf.h, excluding typedefs.
# Static implementation helpers and libcurl codec helpers are not public zlib aliases.
ZLIB_ALIASES = frozenset("""
_dist_code _length_code _tr_align _tr_flush_bits _tr_flush_block _tr_init
_tr_stored_block _tr_tally adler32 adler32_combine adler32_combine64 adler32_z compress
compress2 compress_z compress2_z compressBound compressBound_z crc32 crc32_combine
crc32_combine64 crc32_combine_gen crc32_combine_gen64 crc32_combine_op crc32_z deflate
deflateBound deflateBound_z deflateCopy deflateEnd deflateGetDictionary deflateInit
deflateInit2 deflateInit2_ deflateInit_ deflateParams deflatePending deflatePrime
deflateReset deflateResetKeep deflateSetDictionary deflateSetHeader deflateTune
deflateUsed deflate_copyright get_crc_table gz_error gz_intmax gz_strwinerror gzbuffer
gzclearerr gzclose gzclose_r gzclose_w gzdirect gzdopen gzeof gzerror gzflush gzfread
gzfwrite gzgetc gzgetc_ gzgets gzoffset gzoffset64 gzopen gzopen64 gzopen_w gzprintf
gzputc gzputs gzread gzrewind gzseek gzseek64 gzsetparams gztell gztell64 gzungetc
gzvprintf gzwrite inflate inflateBack inflateBackEnd inflateBackInit inflateBackInit_
inflateCodesUsed inflateCopy inflateEnd inflateGetDictionary inflateGetHeader
inflateInit inflateInit2 inflateInit2_ inflateInit_ inflateMark inflatePrime
inflateReset inflateReset2 inflateResetKeep inflateSetDictionary inflateSync
inflateSyncPoint inflateUndermine inflateValidate inflate_copyright inflate_fast
inflate_table inflate_fixed uncompress uncompress2 uncompress_z uncompress2_z zError
zcalloc zcfree zlibCompileFlags zlibVersion
""".split())
ZLIB_NAME = re.compile(r"(?:z_)?(?:" + "|".join(re.escape(name) for name in sorted(ZLIB_ALIASES)) + r")")


def symbols(output):
    """Read GNU readelf symbol rows, including version-qualified imports."""
    result = []
    for line in output.splitlines():
        columns = line.split(None, 7)
        if (len(columns) != 8 or not columns[0].endswith(":")
                or not columns[0][:-1].isdigit()):
            continue
        name = columns[7].split()[0].split("@", 1)[0]
        result.append({
            "name": name, "type": columns[3], "binding": columns[4],
            "visibility": columns[5], "section": columns[6],
        })
    return result


def verify_tables(full, dynamic):
    """Reject interposition and incomplete or externally resolved definitions."""
    if not full or not dynamic:
        raise ValueError("The native addon must retain inspectable ELF symbol tables")
    if any(ZLIB_NAME.fullmatch(item["name"]) for item in dynamic):
        raise ValueError("The native addon exposes or imports a dynamic zlib symbol")
    private = set()
    for item in full:
        name = item["name"]
        if not ZLIB_NAME.fullmatch(name):
            continue
        if (not name.startswith("z_") or item["section"] == "UND"
                or (item["binding"] != "LOCAL" and item["visibility"] != "HIDDEN")):
            raise ValueError("The native addon contains a non-private zlib symbol")
        if item["type"] == "FUNC":
            private.add(name)
    if not REQUIRED.issubset(private):
        raise ValueError("The native addon lacks required private compression definitions")
    return sorted(private)


def verify_binary(path):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 4 <= info.st_size <= 128 * 1024 * 1024:
        raise ValueError("The native addon is not a bounded regular ELF file")
    with path.open("rb") as source:
        if source.read(4) != b"\x7fELF":
            raise ValueError("The native addon is not an ELF binary")
    environment = {**os.environ, "LC_ALL": "C"}

    def read(option):
        return subprocess.run(
            ["readelf", "--wide", option, "--", str(path)],
            check=True, capture_output=True, text=True, timeout=30, env=environment,
        ).stdout

    private = verify_tables(symbols(read("--symbols")), symbols(read("--dyn-syms")))
    return {
        "status": "PASS", "bytes": info.st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "privateZlibFunctions": private,
        "scope": "ELF isolation only; runtime version and real gzip broker tests are separate",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    options = parser.parse_args()
    print(json.dumps(verify_binary(options.binary)))


if __name__ == "__main__":
    main()

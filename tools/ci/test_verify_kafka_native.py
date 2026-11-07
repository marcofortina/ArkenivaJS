# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Negative controls for the Linux native Kafka symbol-isolation gate."""

import unittest

import verify_kafka_native as verifier


def symbol(name, binding="LOCAL", visibility="DEFAULT", section="12", kind="FUNC"):
    return {
        "name": name, "type": kind, "binding": binding,
        "visibility": visibility, "section": section,
    }


class NativeIsolationTests(unittest.TestCase):
    def setUp(self):
        self.full = [symbol(name) for name in verifier.REQUIRED]
        self.dynamic = [symbol("node_module_register", "GLOBAL", section="UND")]

    def test_local_and_hidden_definitions_are_accepted(self):
        self.assertEqual(set(verifier.verify_tables(self.full, self.dynamic)), verifier.REQUIRED)
        hidden = [{**item, "binding": "GLOBAL", "visibility": "HIDDEN"} for item in self.full]
        self.assertEqual(set(verifier.verify_tables(hidden, self.dynamic)), verifier.REQUIRED)

    def test_missing_compression_definition_is_rejected(self):
        for missing in verifier.REQUIRED:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                verifier.verify_tables([item for item in self.full if item["name"] != missing], self.dynamic)

    def test_default_visible_and_undefined_prefixed_symbols_are_rejected(self):
        for replacement in [symbol("z_inflate", "GLOBAL"), symbol("z_inflate", section="UND")]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                verifier.verify_tables(self.full + [replacement], self.dynamic)

    def test_dynamic_plain_or_prefixed_apis_are_rejected(self):
        for name in ["inflate", "inflateReset2", "deflateInit2_", "zlibVersion", "gzread", "z_inflate"]:
            for section in ["UND", "12"]:
                with self.subTest(name=name, section=section), self.assertRaises(ValueError):
                    verifier.verify_tables(self.full, self.dynamic + [symbol(name, "GLOBAL", section=section)])

    def test_hidden_plain_copy_is_rejected(self):
        with self.assertRaises(ValueError):
            verifier.verify_tables(self.full + [symbol("inflate")], self.dynamic)

    def test_empty_or_stripped_tables_are_rejected(self):
        for full, dynamic in [(self.full, []), ([], self.dynamic)]:
            with self.assertRaises(ValueError):
                verifier.verify_tables(full, dynamic)

    def test_versioned_imports_are_parsed_before_comparison(self):
        output = """Symbol table '.dynsym' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflate@ZLIB_1.2.0 (3)
     2: 0000000000001230    32 FUNC    LOCAL  DEFAULT   12 z_inflate
"""
        parsed = verifier.symbols(output)
        self.assertEqual([item["name"] for item in parsed], ["inflate", "z_inflate"])
        with self.assertRaises(ValueError):
            verifier.verify_tables(self.full, parsed)

    def test_local_implementation_and_libcurl_codec_helpers_are_not_zlib_aliases(self):
        helpers = ["deflate_stored", "deflate_fast", "deflateStateCheck", "adler32_combine_",
                   "deflate_do_write", "gzip_do_init", "inflate_stream", "compress_block",
                   "deflate_encoding", "gzip_encoding", "inflateStateCheck"]
        for name in helpers:
            self.assertIsNone(verifier.ZLIB_NAME.fullmatch(name))
        self.assertEqual(set(verifier.verify_tables(
            self.full + [symbol(name) for name in helpers], self.dynamic,
        )), verifier.REQUIRED)

    def test_unrelated_native_dependencies_do_not_match(self):
        for name in ["ZSTD_decompress", "rd_kafka_produce", "SSL_read", "__cxa_finalize"]:
            self.assertIsNone(verifier.ZLIB_NAME.fullmatch(name))


if __name__ == "__main__":
    unittest.main()

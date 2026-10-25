"""Reject unsafe fixture inputs before creating credentials or invoking privileged tools."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from prepare import prepare


class PreparationTests(unittest.TestCase):
    def test_invalid_versions_and_ports_allocate_nothing(self):
        with tempfile.TemporaryDirectory(prefix="arkenivajs-postgres-inputs-") as temporary:
            destination = Path(temporary) / "fixture"
            for options in [
                {"server_major": 16}, {"server_major": 19},
                {"port": 0}, {"port": 1023}, {"port": 65536}, {"port": True},
                {"wrong_san_port": -1}, {"wrong_san_port": 15432},
            ]:
                with self.subTest(options=options):
                    with self.assertRaises(ValueError):
                        prepare(destination, **options)
                    self.assertFalse(destination.exists())

    def test_a_product_checkout_cannot_receive_fixture_secrets(self):
        root = Path(__file__).resolve().parents[4]
        destination = root / "unexpected-postgres-fixture"
        self.assertTrue((root / ".git").exists())
        with self.assertRaises(ValueError):
            prepare(destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()

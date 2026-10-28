import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("cluster", Path(__file__).with_name("cluster.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)


class PrivateLabInputTests(unittest.TestCase):
    def test_private_permissions_hold_even_with_a_permissive_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            previous = os.umask(0)
            try:
                cluster.write_private(path, "synthetic input")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), "synthetic input")

    def test_existing_input_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            cluster.write_private(path, "original")
            with self.assertRaises(FileExistsError):
                cluster.write_private(path, "replacement")
            self.assertEqual(path.read_text(), "original")

    def test_existing_symlink_cannot_overwrite_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.write_text("unrelated data")
            path = Path(temporary) / "input"
            path.symlink_to(target)
            with self.assertRaises(FileExistsError):
                cluster.write_private(path, "replacement")
            self.assertEqual(target.read_text(), "unrelated data")


if __name__ == "__main__":
    unittest.main()

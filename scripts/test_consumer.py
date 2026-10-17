import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("consumer", Path(__file__).with_name("consumer-interop.py"))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class ConsumerWindowTests(unittest.TestCase):
    def test_new_native_sdk_cannot_silently_extend_a_pinned_consumer_fixture(self):
        with patch.object(sys, "argv", ["consumer-interop.py", "--keycloak-version", "26.8.1", "--harness", "/unused"]), \
                patch.object(consumer, "identity", side_effect=AssertionError("No build, source or Docker access expected")):
            with self.assertRaisesRegex(ValueError, "No reviewed consumer fixture"):
                consumer.main()


if __name__ == "__main__":
    unittest.main()

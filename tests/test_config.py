from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rudrai.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_schema_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".rudrai.yaml").write_text(
                "max_file_size: 2048\n"
                "exclude:\n"
                "  - vendor/**\n"
                "suppressions:\n"
                "  - rule_id: RAI-DEP-003\n"
                "    path: requirements.txt\n"
                "    reason: reviewed\n"
                "    expires: 2099-01-01\n",
                encoding="utf-8",
            )
            config = load_config(root)
            self.assertEqual(2048, config.max_file_size)
            self.assertEqual(["vendor/**"], config.exclude)
            self.assertTrue(config.suppressions[0].applies("RAI-DEP-003", "requirements.txt"))

    def test_unknown_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".rudrai.yaml").write_text("custom_rules: true\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(root)


if __name__ == "__main__":
    unittest.main()


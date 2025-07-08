import os
import re
import sys
import unittest

import yaml

# Add project root to sys.path to allow imports if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestRuleCompilation(unittest.TestCase):
    def test_murmur_rule_compilation(self):
        rules_path = os.path.join(os.path.dirname(__file__), "..", "rules", "murmur.yaml")
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        self.assertIsInstance(rules, dict)

        # Test lines for each level
        test_lines = {
            "critical": [
                "Connection closed: Error during SSL handshake: error:0A000102:SSL routines::unsupported protocol [13]",
                "Wrong certificate or password for existing user from 1.2.3.4",
                "Rejected connection from 192.168.1.1:1234",
            ],
            "suspicious": [
                "New connection: 192.168.1.100:54321",
                "Connection closed: The remote host closed the connection [1]",
            ],
        }

        for level in ("critical", "suspicious"):
            for pattern in rules.get(level, []):
                regex = re.compile(pattern)
                # Check if any test line matches this pattern
                if not any(regex.search(line) for line in test_lines.get(level, [])):
                    print(f"No match for pattern: {pattern} (level: {level})")
                    self.fail(f"Pattern did not match any test lines: {pattern}")


if __name__ == "__main__":
    unittest.main()

import unittest
from log_detective import RuleWatcher

class TestRuleMatching(unittest.TestCase):
    def test_critical_detection(self):
        watcher = RuleWatcher("/var/log/test.log", "rules/test.yaml", 1, {"host": "localhost", "topic_base": "log"})
        line = "Connection closed: Error during SSL handshake"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

if __name__ == '__main__':
    unittest.main()
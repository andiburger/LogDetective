import unittest
from unittest.mock import patch

from log_detective.log_detective import RuleWatcher


# Ensure the rules directory is in the Python path
class TestRuleMatching(unittest.TestCase):
    def test_critical_detection(self):
        watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/test.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "Connection closed: Error during SSL handshake"
        results = watcher.check_line(line)
        self.assertFalse(any(r[0] == "critical" for r in results))

    def test_ufw_critical(self):
        watcher = RuleWatcher(
            "/var/log/ufw.log",
            "rules/ufw.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "Jul  4 01:00:00 raspberrypi kernel: [123456.789012] UFW BLOCK IN=eth0 OUT= MAC= SRC=192.168.1.120 DST=192.168.1.5 ..."
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_fail2ban_critical(self):
        watcher = RuleWatcher(
            "/var/log/fail2ban.log",
            "rules/fail2ban.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "2025-07-04 01:00:00,000 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.168.1.130"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_murmur_critical(self):
        watcher = RuleWatcher(
            "/var/log/mumble-server/mumble-server.log",
            "rules/murmur.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = (
            "<W>2025-07-03 01:03:34.256 Connection closed: Error during SSL handshake: "
            "error:0A000102:SSL routines::unsupported protocol [13]"
        )
        results = watcher.check_line(line)
        print("Matched results:", results)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_ssh_critical(self):
        watcher = RuleWatcher(
            "/var/log/auth.log",
            "rules/ssh.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "Jul  4 00:00:01 raspberrypi sshd[12345]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_ssh_suspicious(self):
        watcher = RuleWatcher(
            "/var/log/auth.log",
            "rules/ssh.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "Jul  4 00:00:02 raspberrypi sshd[12345]: Connection closed by authenticating user"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "suspicious" for r in results))

    def test_no_match(self):
        watcher = RuleWatcher(
            "/var/log/empty.log",
            "rules/ssh.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        line = "This line should not match anything."
        results = watcher.check_line(line)
        self.assertEqual(len(results), 0)

    @patch("log_detective.log_detective.requests.post")
    def test_send_influxdb_success(self, mock_post):
        mock_post.return_value.status_code = 204

        watcher = RuleWatcher(
            path="/var/log/test.log",
            rule_file="rules/ssh.yaml",
            verbosity=1,
            mqtt_config={"host": "localhost", "topic_base": "log"},
            influxdb_config={"host": "localhost", "port": 8086, "database": "testdb"},
        )
        watcher.send_influxdb("critical", "This is a test message")

        mock_post.assert_called_once()

    def test_rule_reload(self):
        watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/ssh.yaml",
            1,
            {"host": "localhost", "topic_base": "log"},
            None,
        )
        initial_rules = watcher.rules
        watcher._load_rules()  # Triggert Reload
        self.assertEqual(initial_rules, watcher.rules)


class TestMQTTSend(unittest.TestCase):
    @patch("log_detective.log_detective.publish.single")
    def test_send_mqtt_success(self, mock_publish):
        watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/ssh.yaml",
            1,
            {"host": "192.168.178.160", "topic_base": "logdetective", "port": 1883},
            None,
        )
        print("Testing MQTT send...")
        watcher.send_mqtt("critical", "Test critical message")
        mock_publish.assert_called_once()
        args, kwargs = mock_publish.call_args
        self.assertIn("logdetective/test/critical", args)
        self.assertIn("Test critical message", kwargs["payload"])


if __name__ == "__main__":
    unittest.main()

import unittest
from log_detective.log_detective import RuleWatcher
from unittest.mock import patch

class TestRuleMatching(unittest.TestCase):
    def test_critical_detection(self):
        watcher = RuleWatcher("/var/log/test.log", "rules/test.yml", 1, {"host": "localhost", "topic_base": "log"})
        line = "Connection closed: Error during SSL handshake"
        results = watcher.check_line(line)
        self.assertFalse(any(r[0] == "critical" for r in results))

    def test_ufw_critical(self):
        watcher = RuleWatcher("/var/log/ufw.log", "rules/ufw.yml", 1, {"host": "localhost", "topic_base": "log"})
        line = "Jul  4 01:00:00 raspberrypi kernel: [123456.789012] UFW BLOCK IN=eth0 OUT= MAC= SRC=192.168.1.120 DST=192.168.1.5 ..."
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_fail2ban_critical(self):
        watcher = RuleWatcher("/var/log/fail2ban.log", "rules/fail2ban.yml", 1, {"host": "localhost", "topic_base": "log"})
        line = "2025-07-04 01:00:00,000 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.168.1.130"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))
    def test_murmur_critical(self):
        watcher = RuleWatcher("/var/log/mumble-server/mumble-server.log", "rules/murmur.yml", 1, {"host": "localhost", "topic_base": "log"})
        line = "<W>2025-07-03 01:03:34.256 Connection closed: Error during SSL handshake: error:0A000102:SSL routines::unsupported protocol [13]"
        results = watcher.check_line(line)
        print("Matched results:", results)
        self.assertTrue(any(r[0] == "critical" for r in results))

    def test_ssh_critical(self):
        watcher = RuleWatcher("/var/log/auth.log", "rules/ssh.yml", 1, {"host": "localhost", "topic_base": "log"})
        line = "Jul  4 00:00:01 raspberrypi sshd[12345]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
        results = watcher.check_line(line)
        self.assertTrue(any(r[0] == "critical" for r in results))

class TestMQTTSend(unittest.TestCase):
    @patch("log_detective.log_detective.publish.single")
    def test_send_mqtt_success(self, mock_publish):
        watcher = RuleWatcher("/var/log/test.log", "rules/ssh.yml", 1, {
            "host": "192.168.178.160",
            "topic_base": "logdetective",
            "port": 1883
        })
        print("Testing MQTT send...")
        watcher.send_mqtt("critical", "Test critical message")
        mock_publish.assert_called_once()
        args, kwargs = mock_publish.call_args
        self.assertIn("logdetective/test/critical", args)
        self.assertIn("Test critical message", kwargs["payload"])

if __name__ == '__main__':
    unittest.main()
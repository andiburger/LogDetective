import json
import os
import unittest

# Additional test: Test that send_mqtt includes geoip fields in payload
from unittest.mock import MagicMock, patch

from geoip2.database import Reader  # type: ignore

from log_detective.log_detective import RuleWatcher


class TestGeoIPLookup(unittest.TestCase):
    def setUp(self):
        # Standard GeoIP-Datenbankpfad
        self.geoip_path = "GeoLite2-City.mmdb"
        if not os.path.exists(self.geoip_path):
            self.skipTest(f"GeoIP DB not found at {self.geoip_path}")
        self.reader = Reader(self.geoip_path)

    def tearDown(self):
        self.reader.close()

    def test_lookup_google_dns(self):
        # 8.8.8.8 = Google DNS
        response = self.reader.city("8.8.8.8")
        self.assertIsNotNone(response.location.latitude)
        self.assertIsNotNone(response.location.longitude)
        self.assertGreater(response.location.latitude, -90)
        self.assertLess(response.location.latitude, 90)
        self.assertGreater(response.location.longitude, -180)
        self.assertLess(response.location.longitude, 180)

    def test_invalid_ip(self):
        # Ungültige IP-Adresse
        with self.assertRaises(Exception):
            self.reader.city("999.999.999.999")

    def test_lookup_ipv6_google(self):
        # IPv6 von Google Public DNS
        response = self.reader.city("2001:4860:4860::8888")
        self.assertIsNotNone(response.location.latitude)
        self.assertIsNotNone(response.location.longitude)
        self.assertGreater(response.location.latitude, -90)
        self.assertLess(response.location.latitude, 90)
        self.assertGreater(response.location.longitude, -180)
        self.assertLess(response.location.longitude, 180)


class TestSendInfluxDB(unittest.TestCase):
    def setUp(self):
        self.watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/ssh.yaml",
            verbosity=1,
            mqtt_config={"host": "localhost", "topic_base": "log"},
            influxdb_config={"host": "localhost", "port": 8086, "database": "logdetective"},
            use_geoip=True,
        )

    @patch("log_detective.log_detective.geoip_reader")
    @patch("requests.post")
    def test_send_influxdb_with_geoip(self, mock_post, mock_geoip_reader):
        mock_location = MagicMock()
        mock_location.latitude = 37.751
        mock_location.longitude = -97.822
        mock_city = MagicMock()
        mock_city.location = mock_location
        mock_geoip_reader.city.return_value = mock_city
        mock_post.return_value.status_code = 204

        # Adjust log line for real ip pattern matching
        self.watcher.send_influxdb(
            "critical",
            "sshd[12345]: Failed password for invalid user root from 8.8.8.8 port 22 ssh2",
        )

        args, kwargs = mock_post.call_args
        data = kwargs["data"]
        self.assertIn("ip=8.8.8.8", data)
        self.assertIn("geo_lat=37.751", data)
        self.assertIn("geo_lon=-97.822", data)

    @patch("requests.post")
    def test_send_influxdb_no_geoip(self, mock_post):
        self.watcher.use_geoip = False
        mock_post.return_value.status_code = 204
        # Adjust log line for real ip pattern matching
        self.watcher.send_influxdb(
            "critical", "sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2"
        )
        args, kwargs = mock_post.call_args
        data = kwargs["data"]
        self.assertIn("ip=1.2.3.4", data or "")
        self.assertNotIn("geo_lat", data)
        self.assertNotIn("geo_lon", data)


class TestEndToEndDetection(unittest.TestCase):
    @patch("log_detective.log_detective.RuleWatcher.send_mqtt")
    @patch("log_detective.log_detective.RuleWatcher.send_influxdb")
    def test_check_line_and_notification(self, mock_influx, mock_mqtt):
        watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/ssh.yaml",
            verbosity=1,
            mqtt_config={"host": "localhost", "topic_base": "log"},
            influxdb_config={"host": "localhost", "port": 8086, "database": "logdetective"},
            use_geoip=False,
        )
        test_line = "Jul  4 00:00:02 raspberrypi sshd[12345]: Failed password for invalid user root from 8.8.8.8 port 22 ssh2"
        results = watcher.check_line(test_line)
        call_count = 0
        for level, line in results:
            watcher.send_mqtt(level, line)
            watcher.send_influxdb(level, line)
            call_count += 1

        self.assertGreaterEqual(mock_mqtt.call_count, 1)
        self.assertGreaterEqual(mock_influx.call_count, 1)

        mqtt_args, _ = mock_mqtt.call_args
        self.assertIn("critical", mqtt_args)
        self.assertIn("8.8.8.8", mqtt_args[1])  # IP is in the log line argument


class TestSendMQTTWithGeoIP(unittest.TestCase):
    @patch("log_detective.log_detective.publish.single")
    @patch("log_detective.log_detective.geoip_reader")
    def test_send_mqtt_with_geoip_fields(self, mock_geoip_reader, mock_publish):
        mock_location = MagicMock(latitude=50.1, longitude=8.6)
        mock_city = MagicMock(location=mock_location)
        mock_geoip_reader.city.return_value = mock_city

        watcher = RuleWatcher(
            "/var/log/test.log",
            "rules/test.yaml",
            verbosity=1,
            mqtt_config={"host": "localhost", "topic_base": "log/test"},
            influxdb_config=None,
            use_geoip=True,
        )

        # Add mock rule that will match the test log line
        import re

        watcher.rules = {
            "critical": [re.compile(r"Failed password .* from (\d{1,3}\.){3}\d{1,3}")],
            "suspicious": [],
        }

        line = "sshd[12345]: Failed password for invalid user admin from 8.8.8.8 port 22 ssh2"
        watcher.extract_ip = lambda line: "8.8.8.8"
        for level, matched in watcher.check_line(line):
            watcher.send_mqtt(level, matched)

        mock_publish.assert_called_once()
        payload_arg = mock_publish.call_args[1]["payload"]
        payload_dict = json.loads(payload_arg)

        assert payload_dict["ip"] == "8.8.8.8"
        assert abs(payload_dict["geo_lat"] - 50.1) < 0.01
        assert abs(payload_dict["geo_lon"] - 8.6) < 0.01
        assert payload_dict["level"] == "critical"
        assert "sshd" in payload_dict["message"]
        assert "sshd" in payload_dict["message"]


if __name__ == "__main__":
    unittest.main()

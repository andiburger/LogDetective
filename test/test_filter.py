# test_filter.py
import pytest

from log_detective.log_detective import RuleWatcher


class DummyMQTT:
    host = "localhost"
    topic_base = "logdetective"


class TestExtractIp:
    def setup_method(self):
        # Minimaler RuleWatcher ohne echte Konfigs
        self.watcher = RuleWatcher(
            path="dummy.log",
            rule_file="rules.yaml",  # darf existieren oder leer sein
            verbosity=1,
            mqtt_config=None,
            influxdb_config=None,
            use_geoip=False,
        )

    def test_ignore_year_in_timestamp(self):
        line = "2025-09-02 16:22:37.412 something happened"
        assert self.watcher.extract_ip(line) is None

    def test_ignore_plain_number(self):
        line = "Connection closed by 2025"
        assert self.watcher.extract_ip(line) is None

    def test_extract_ipv4(self):
        line = "Accepted connection from 192.168.1.10 port 22"
        assert self.watcher.extract_ip(line) == "192.168.1.10"

    def test_extract_ipv4_with_port(self):
        line = "Client 10.0.0.1:8080 disconnected"
        assert self.watcher.extract_ip(line) == "10.0.0.1"

    def test_extract_ipv6(self):
        line = "Connection from 2001:db8::1 established"
        assert self.watcher.extract_ip(line) == "2001:db8::1"

    def test_extract_bracketed_ipv6(self):
        line = "Host [fe80::1] responded"
        assert self.watcher.extract_ip(line) == "fe80::1"

    def test_extract_long_hex_string(self):
        line = "Weird ID deadbeefcafebabe seen"
        assert self.watcher.extract_ip(line) == "deadbeefcafebabe"

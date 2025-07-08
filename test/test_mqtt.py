import os
import sys

from log_detective.log_detective import RuleWatcher

# Ensure project root is in PYTHONPATH for pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


mqtt_config = {"host": "192.168.178.160", "topic_base": "logdetective", "port": 1883}


def test_send_mqtt_message():
    watcher = RuleWatcher("/var/log/test.log", "rules/ssh.yml", 1, mqtt_config, None)
    # Send a test MQTT message (can be mocked if needed)
    watcher.send_mqtt("critical", "Manual test message")
    print("MQTT message sent successfully.")
    print("MQTT message sent successfully.")

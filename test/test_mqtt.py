import os
import sys
from unittest.mock import patch

from log_detective.log_detective import RuleWatcher

# Ensure project root is in PYTHONPATH for pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


mqtt_config = {"host": "192.168.178.160", "topic_base": "logdetective", "port": 1883}


def test_send_mqtt_message():
    watcher = RuleWatcher("/var/log/test.log", "rules/ssh.yml", 1, mqtt_config, None)
    with patch("paho.mqtt.publish.single") as mock_single:
        watcher.send_mqtt("critical", "Manual test message")
        mock_single.assert_called_once()
        args, kwargs = mock_single.call_args
        # Extract topic and payload from args or kwargs
        # paho.mqtt.publish.single signature: single(topic, payload=None, qos=0, retain=False, hostname="localhost", port=1883, client_id="", keepalive=60, will=None, auth=None, tls=None, protocol=mqtt.MQTTv311, transport="tcp", **kwargs)
        # So topic is args[0] or kwargs['topic'], payload is args[1] or kwargs['payload']
        if args:
            topic = args[0]
            payload = args[1] if len(args) > 1 else None
        else:
            topic = kwargs.get("topic")
            payload = kwargs.get("payload")
        assert topic is not None and "logdetective" in topic
        assert payload is not None and "Manual test message" in payload
    print("MQTT message sent successfully.")

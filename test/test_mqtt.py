from log_detective.log_detective import RuleWatcher

mqtt_config = {
    "host": "192.168.178.160",
    "topic_base": "logdetective",
    "port": 1883
}

watcher = RuleWatcher(
    "/var/log/test.log",
    "rules/ssh.yml",
    1,
    mqtt_config,
    None
)
watcher.send_mqtt("critical", "Manual test message")

print("MQTT message sent successfully.")
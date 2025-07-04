import os
import time
import yaml
import re
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import paho.mqtt.client as mqtt

class RuleManager:
    def __init__(self):
        self.rules = {}

    def load_rules(self, rule_path):
        try:
            with open(rule_path, 'r') as f:
                data = yaml.safe_load(f)
                self.rules[rule_path] = {
                    "critical": [re.compile(p) for p in data.get('critical', [])],
                    "suspicious": [re.compile(p) for p in data.get('suspicious', [])]
                }
        except Exception as e:
            print(f"[!] Error loading {rule_path}: {e}")

    def reload_rule_file(self, rule_path):
        print(f"[~] Reloading rules: {rule_path}")
        self.load_rules(rule_path)

    def match(self, rule_path, line):
        results = []
        if rule_path not in self.rules:
            return results
        for level, patterns in self.rules[rule_path].items():
            for pat in patterns:
                if pat.search(line):
                    results.append(level)
        return results

class RuleWatcher(FileSystemEventHandler):
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith('.yaml'):
            return
        self.rule_manager.reload_rule_file(event.src_path)

class LogMonitor:
    def __init__(self, config_path):
        self.config = self.load_config(config_path)
        self.rule_manager = RuleManager()
        self.verbosity = self.config.get('verbosity', 1)

        # MQTT
        mqtt_config = self.config.get('mqtt', {})
        self.mqtt_host = mqtt_config.get('host', 'localhost')
        self.mqtt_port = mqtt_config.get('port', 1883)
        self.mqtt_topic = mqtt_config.get('topic', 'log_detective/events')
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)

        self.rule_paths = []

        for entry in self.config['logs']:
            self.rule_manager.load_rules(entry['rules'])
            self.rule_paths.append(entry['rules'])

    def start(self):
        # Watch rule files
        self.start_rule_watcher()

        # Monitor logs
        for entry in self.config['logs']:
            threading.Thread(target=self.monitor_log, args=(entry['path'], entry['rules'])).start()

    def start_rule_watcher(self):
        event_handler = RuleWatcher(self.rule_manager)
        observer = Observer()
        for rule_path in set(self.rule_paths):
            rule_dir = os.path.dirname(rule_path)
            observer.schedule(event_handler, rule_dir, recursive=False)
        observer.start()

    def monitor_log(self, filepath, rule_path):
        try:
            with open(filepath, 'r') as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    matches = self.rule_manager.match(rule_path, line)
                    for level in matches:
                        if self.verbosity >= 1:
                            print(f"[{level.upper()}] {line.strip()}")
                        self.send_mqtt(level, line.strip())
        except Exception as e:
            print(f"[!] Error monitoring {filepath}: {e}")

    def send_mqtt(self, level, message):
        payload = yaml.dump({
            'level': level,
            'message': message
        })
        self.mqtt_client.publish(self.mqtt_topic, payload)

    def load_config(self, path):
        with open(path, 'r') as f:
            return yaml.safe_load(f)

if __name__ == "__main__":
    LogMonitor('config.yaml').start()
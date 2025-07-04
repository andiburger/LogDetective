import os
import time
import yaml # type: ignore
import json
import logging
import signal
import re
import paho.mqtt.publish as publish # type: ignore
from watchdog.observers import Observer # type: ignore
from watchdog.events import FileSystemEventHandler # type: ignore
from hashlib import md5
import requests

PID_FILE = "/var/run/log_detective.pid"
CONFIG_FILE = "config.yaml"
LOG_FILE = "log_detective.log"

# Setup logging to file and console
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logging.getLogger().setLevel(logging.INFO)
logging.getLogger().addHandler(file_handler)
logging.getLogger().addHandler(console_handler)

# Global stop flag
running = True

def write_pid():
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

def handle_shutdown(signum, frame):
    global running
    logging.info("Shutdown signal received.")
    running = False

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

def load_rules(rule_file):
    with open(rule_file, 'r') as f:
        return yaml.safe_load(f)

class RuleWatcher:
    def __init__(self, path, rule_file, verbosity, mqtt_config, influxdb_config):
        self.path = path
        self.rule_file = rule_file
        self.verbosity = verbosity
        self.mqtt_config = mqtt_config
        self.influxdb_config = influxdb_config
        self.rules_hash = None
        self.rules = {}
        self._load_rules()

    def _load_rules(self):
        try:
            with open(self.rule_file, 'rb') as f:
                current_hash = md5(f.read()).hexdigest()
                if current_hash != self.rules_hash:
                    raw_rules = load_rules(self.rule_file)
                    compiled_rules = {}
                    for level in ("critical", "suspicious"):
                        compiled_rules[level] = []
                        for pattern in raw_rules.get(level, []):
                            try:
                                compiled_rules[level].append(re.compile(pattern))
                            except re.error as e:
                                logging.error(f"Invalid regex '{pattern}' in {self.rule_file}: {e}")
                    self.rules = compiled_rules
                    self.rules_hash = current_hash
                    logging.info(f"Reloaded and compiled rules for {self.path}")
        except Exception as e:
            logging.error(f"Error loading rules from {self.rule_file}: {e}")

    def check_line(self, line):
        self._load_rules()
        results = []
        for rule_type in ("critical", "suspicious"):
            for regex in self.rules.get(rule_type, []):
                if regex.search(line):
                    results.append((rule_type, line.strip()))
        return results

    def send_mqtt(self, level, message):
        topic = f"{self.mqtt_config['topic_base']}"
        try:
            topic = f"{self.mqtt_config['topic_base']}/{os.path.basename(self.path).replace('.log','')}/{level}"
            payload = json.dumps({"log": self.path, "level": level, "message": message})
            logging.info(f"MQTT SEND: topic={topic}, payload={payload}")
            print(f"MQTT SEND TRIGGERED: {payload}")
            publish.single(
                topic,
                payload=payload,
                hostname=self.mqtt_config["host"],
                port=self.mqtt_config["port"]
            )
        except Exception as e:
            print(f"MQTT publish failed: {e}")
            publish.single(topic,
                           payload=json.dumps({"error": str(e)}),
                           hostname=self.mqtt_config["host"],
                           port=self.mqtt_config.get("port", 1883))
            print(f"MQTT publish failed: {e}")
            logging.error(f"MQTT publish failed: {e}")

    def process_line(self, line):
        logging.info(f"Processing line: {line.strip()}")
        findings = self.check_line(line)
        logging.info(f"check_line result: {findings}")
        for level, msg in findings:
            logging.info(f"LINE MATCHED [{level}]: {msg}")
            if self.verbosity >= (1 if level == "suspicious" else 0):
                logging.warning(f"{level.upper()} in {self.path}: {msg}")
                self.send_mqtt(level, msg)
                self.send_influxdb(level, msg)

    def send_influxdb(self, level, message):
        influx_cfg = self.influxdb_config
        if not influx_cfg:
            return
        try:
            line = f"log_event,logfile={os.path.basename(self.path)},level={level} value=1"
            response = requests.post(
                f"http://{influx_cfg['host']}:{influx_cfg.get('port', 8086)}/write",
                params={
                    "db": influx_cfg["database"],
                    "u": influx_cfg.get("username", ""),
                    "p": influx_cfg.get("password", "")
                },
                data=line,
                timeout=2
            )
            if response.status_code != 204:
                logging.error(f"InfluxDB write failed: {response.text}")
            else:
                logging.info(f"InfluxDB write success for {level} in {self.path}")
        except Exception as e:
            logging.error(f"Error sending to InfluxDB: {e}")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, watcher):
        logging.info(f"Opening file {watcher.path}")
        self.watcher = watcher
        self._file = open(watcher.path, 'r')
        self._inode = os.fstat(self._file.fileno()).st_ino
        self._file.seek(0, 2)  # Jump to end of file

    def on_modified(self, event):
        logging.info(f"Reading from handle: {self._file.name}")
        logging.info(f"File modified: {event.src_path}")
        if event.src_path != self.watcher.path:
            return
        try:
            current_inode = os.stat(self.watcher.path).st_ino
            if current_inode != self._inode:
                logging.info(f"Detected rotation for {self.watcher.path}. Reopening.")
                self._file.close()
                self._file = open(self.watcher.path, 'r')
                self._inode = current_inode
                # Send MQTT message on logrotate detection
                try:
                    rotate_payload = json.dumps({
                        "status": "logrotated",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "logfile": self.watcher.path
                    })
                    publish.single(
                        f"{self.watcher.mqtt_config.get('topic_base', 'logdetective')}/status",
                        payload=rotate_payload,
                        hostname=self.watcher.mqtt_config["host"],
                        port=self.watcher.mqtt_config.get("port", 1883),
                        auth={
                            "username": self.watcher.mqtt_config.get("username"),
                            "password": self.watcher.mqtt_config.get("password")
                        } if self.watcher.mqtt_config.get("username") else None
                    )
                    logging.info(f"Published logrotate status for {self.watcher.path}")
                except Exception as e:
                    logging.error(f"Failed to publish logrotate status for {self.watcher.path}: {e}")
        except Exception as e:
            logging.error(f"Error checking inode for {self.watcher.path}: {e}")
            return
        while True:
            line = self._file.readline()
            if not line:
                break
            self.watcher.process_line(line)

def start_monitoring():
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)

    mqtt_config = config["mqtt"]
    influxdb_config = config.get("influxdb")
    verbosity = config.get("verbosity", 1)

    # Send MQTT status message on startup
    try:
        status_payload = json.dumps({
            "status": "started",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "pid": os.getpid()
        })
        publish.single(
            f"{mqtt_config.get('base_topic', 'logdetective')}/status",
            payload=status_payload,
            hostname=mqtt_config["host"],
            port=mqtt_config.get("port", 1883),
            auth={
                "username": mqtt_config.get("username"),
                "password": mqtt_config.get("password")
            } if mqtt_config.get("username") else None
        )
        logging.info("Published startup status message to MQTT.")
    except Exception as e:
        logging.error(f"Failed to publish startup status message: {e}")

    observers = []

    for log_cfg in config["logs"]:
        watcher = RuleWatcher(
            log_cfg["path"],
            log_cfg["rule_file"],
            verbosity,
            mqtt_config,
            influxdb_config
        )
        event_handler = LogFileHandler(watcher)
        observer = Observer()
        observer.schedule(event_handler, os.path.dirname(log_cfg["path"]), recursive=False)
        observer.start()
        observers.append(observer)
        logging.info(f"Started monitoring {log_cfg['path']}")

    try:
        while running:
            time.sleep(1)
    finally:
        for obs in observers:
            obs.stop()
            obs.join()
        logging.info("Shutting down log_detective...")

if __name__ == "__main__":
    write_pid()
    start_monitoring()
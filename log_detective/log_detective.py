import json
import logging
import os
import re
import signal
import time
from hashlib import md5
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple

import paho.mqtt.publish as publish  # type: ignore
import requests  # type: ignore
import yaml  # type: ignore
from watchdog.events import FileSystemEventHandler  # type: ignore
from watchdog.observers import Observer  # type: ignore

PID_FILE = "/var/run/log_detective.pid"
CONFIG_FILE = "config.yaml"
LOG_FILE = "log_detective.log"

# Setup logging to both file and console with timestamps and level info
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logging.getLogger().setLevel(logging.INFO)
logging.getLogger().addHandler(file_handler)
logging.getLogger().addHandler(console_handler)

# Global flag to control main loop
running: bool = True


def write_pid() -> None:
    """
    Write the current process ID to a PID file.
    Useful for process management.
    """
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def handle_shutdown(signum: int, frame: Optional[FrameType]) -> None:
    """
    Signal handler for graceful shutdown on SIGINT and SIGTERM.
    Sets the global running flag to False to exit main loop.
    """
    global running
    logging.info("Shutdown signal received.")
    running = False


# Register signal handlers for termination signals
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


def load_rules(rule_file: str) -> Dict[str, Any]:
    """
    Load YAML rule definitions from a file.

    Args:
        rule_file: Path to the YAML rules file.

    Returns:
        Dictionary parsed from YAML with rule patterns.
    """
    with open(rule_file, "r") as f:
        return yaml.safe_load(f)


class RuleWatcher:
    """
    Watches a log file for new lines and applies regex-based rules
    to detect suspicious or critical log entries.
    Can send notifications to MQTT and metrics to InfluxDB.
    """

    def __init__(
        self,
        path: str,
        rule_file: str,
        verbosity: int,
        mqtt_config: Dict[str, Any],
        influxdb_config: Optional[Dict[str, Any]],
    ) -> None:
        """
        Initialize RuleWatcher instance.

        Args:
            path: Path to the log file to watch.
            rule_file: Path to YAML file with regex rules.
            verbosity: Verbosity level for notifications.
            mqtt_config: Configuration dictionary for MQTT.
            influxdb_config: Optional configuration for InfluxDB.
        """
        self.path: str = path
        self.rule_file: str = rule_file
        self.verbosity: int = verbosity
        self.mqtt_config: Dict[str, Any] = mqtt_config
        self.influxdb_config: Optional[Dict[str, Any]] = influxdb_config
        self.rules_hash: Optional[str] = None
        self.rules: Dict[str, List[re.Pattern]] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """
        Load and compile regex patterns from the rule file.
        Only reload if file content changed (detected via md5 hash).
        """
        try:
            with open(self.rule_file, "rb") as f:
                current_hash = md5(f.read()).hexdigest()
                if current_hash != self.rules_hash:
                    raw_rules = load_rules(self.rule_file)
                    compiled_rules: Dict[str, List[re.Pattern]] = {}
                    for level in ("critical", "suspicious"):
                        compiled_rules[level] = []
                        for pattern in raw_rules.get(level, []):  # type: ignore
                            try:
                                compiled_rules[level].append(re.compile(pattern))
                            except re.error as e:
                                logging.error(f"Invalid regex '{pattern}' in {self.rule_file}: {e}")
                    self.rules = compiled_rules
                    self.rules_hash = current_hash
                    logging.info(f"Reloaded and compiled rules for {self.path}")
        except Exception as e:
            logging.error(f"Error loading rules from {self.rule_file}: {e}")

    def check_line(self, line: str) -> List[Tuple[str, str]]:
        """
        Check a single log line against all compiled regex rules.

        Args:
            line: Log line to check.

        Returns:
            List of tuples (level, matched_line) for all matches.
        """
        self._load_rules()
        results: List[Tuple[str, str]] = []
        for rule_type in ("critical", "suspicious"):
            for regex in self.rules.get(rule_type, []):
                if regex.search(line):
                    results.append((rule_type, line.strip()))
        return results

    def send_mqtt(self, level: str, message: str) -> None:
        """
        Publish a JSON payload about a log event to the MQTT broker.

        Args:
            level: Severity level ('critical' or 'suspicious').
            message: The matched log message.
        """
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
                port=self.mqtt_config["port"],
            )
        except Exception as e:
            print(f"MQTT publish failed: {e}")
            publish.single(
                topic,
                payload=json.dumps({"error": str(e)}),
                hostname=self.mqtt_config["host"],
                port=self.mqtt_config.get("port", 1883),
            )
            logging.error(f"MQTT publish failed: {e}")

    def process_line(self, line: str) -> None:
        """
        Process a new log line: check against rules, log matches,
        and send notifications to MQTT and InfluxDB if needed.

        Args:
            line: New line read from the log file.
        """
        logging.info(f"Processing line: {line.strip()}")
        findings = self.check_line(line)
        logging.info(f"check_line result: {findings}")
        for level, msg in findings:
            logging.info(f"LINE MATCHED [{level}]: {msg}")
            if self.verbosity >= (1 if level == "suspicious" else 0):
                logging.warning(f"{level.upper()} in {self.path}: {msg}")
                self.send_mqtt(level, msg)
                self.send_influxdb(level, msg)

    def send_influxdb(self, level: str, message: str) -> None:
        """
        Send a log event metric to InfluxDB with optional IP tag extraction.

        Args:
            level: Severity level.
            message: Log message text.
        """
        influx_cfg = self.influxdb_config
        if not influx_cfg:
            return
        try:
            # Extract IPv4 or IPv6 address from the message if present
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)", message)
            ip_tag = f",ip={ip_match.group(0)}" if ip_match else ""

            line = f"log_event,logfile={os.path.basename(self.path)},level={level}{ip_tag} value=1"
            response = requests.post(
                f"http://{influx_cfg['host']}:{influx_cfg.get('port', 8086)}/write",
                params={
                    "db": influx_cfg["database"],
                    "u": influx_cfg.get("username", ""),
                    "p": influx_cfg.get("password", ""),
                },
                data=line,
                timeout=2,
            )
            if response.status_code != 204:
                logging.error(f"InfluxDB write failed: {response.text}")
            else:
                logging.info(f"InfluxDB write success for {level} in {self.path}")
        except Exception as e:
            logging.error(f"Error sending to InfluxDB: {e}")


class LogFileHandler(FileSystemEventHandler):
    """
    FileSystemEventHandler subclass that reads new lines from a
    monitored log file and passes them to a RuleWatcher instance.
    """

    def __init__(self, watcher: RuleWatcher) -> None:
        """
        Initialize the handler and open the log file for reading.

        Args:
            watcher: RuleWatcher instance associated with the log file.
        """
        logging.info(f"Opening file {watcher.path}")
        self.watcher: RuleWatcher = watcher
        self._file = open(watcher.path, "r")
        self._inode = os.fstat(self._file.fileno()).st_ino
        self._file.seek(0, 2)  # Seek to end of file to read only new lines

    def on_modified(self, event: Any) -> None:
        """
        Called by watchdog when a file is modified.
        Reads new lines and processes them via RuleWatcher.

        Args:
            event: File system event object.
        """
        logging.info(f"Reading from handle: {self._file.name}")
        logging.info(f"File modified: {event.src_path}")
        if event.src_path != self.watcher.path:
            return
        try:
            current_inode = os.stat(self.watcher.path).st_ino
            if current_inode != self._inode:
                logging.info(f"Detected rotation for {self.watcher.path}. Reopening.")
                self._file.close()
                self._file = open(self.watcher.path, "r")
                self._inode = current_inode
                # Send MQTT message on logrotate detection
                try:
                    rotate_payload = json.dumps(
                        {
                            "status": "logrotated",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "logfile": self.watcher.path,
                        }
                    )
                    publish.single(
                        f"{self.watcher.mqtt_config.get('topic_base', 'logdetective')}/status",
                        payload=rotate_payload,
                        hostname=self.watcher.mqtt_config["host"],
                        port=self.watcher.mqtt_config.get("port", 1883),
                        auth=(
                            {
                                "username": self.watcher.mqtt_config.get("username"),
                                "password": self.watcher.mqtt_config.get("password"),
                            }
                            if self.watcher.mqtt_config.get("username")
                            else None
                        ),
                        retain=True,
                    )
                    logging.info(f"Published logrotate status for {self.watcher.path}")
                except Exception as e:
                    logging.error(
                        f"Failed to publish logrotate status for {self.watcher.path}: {e}"
                    )
        except Exception as e:
            logging.error(f"Error checking inode for {self.watcher.path}: {e}")
            return
        while True:
            line = self._file.readline()
            if not line:
                break
            self.watcher.process_line(line)


def start_monitoring() -> None:
    """
    Main entry point: Load configuration, initialize watchers and observers,
    start monitoring all configured log files until shutdown signal.
    """
    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)

    mqtt_config: Dict[str, Any] = config["mqtt"]
    influxdb_config: Optional[Dict[str, Any]] = config.get("influxdb")
    verbosity: int = config.get("verbosity", 1)

    # Publish startup status message to MQTT
    try:
        status_payload = json.dumps(
            {
                "status": "started",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "pid": os.getpid(),
            }
        )
        publish.single(
            f"{mqtt_config.get('base_topic', 'logdetective')}/status",
            payload=status_payload,
            hostname=mqtt_config["host"],
            port=mqtt_config.get("port", 1883),
            auth=(
                {"username": mqtt_config.get("username"), "password": mqtt_config.get("password")}
                if mqtt_config.get("username")
                else None
            ),
            retain=True,
        )
        logging.info("Published startup status message to MQTT.")
    except Exception as e:
        logging.error(f"Failed to publish startup status message: {e}")

    observers: List[Observer] = []

    for log_cfg in config["logs"]:
        watcher = RuleWatcher(
            log_cfg["path"], log_cfg["rule_file"], verbosity, mqtt_config, influxdb_config
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

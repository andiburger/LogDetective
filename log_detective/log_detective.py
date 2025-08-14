# --- CLI/interactive additions ---
import argparse
import json
import logging
import os
import re
import signal
import threading
import time
from collections import deque
from hashlib import md5
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple

import geoip2.database  # type: ignore
import paho.mqtt.publish as publish  # type: ignore
import requests  # type: ignore
import yaml  # type: ignore
from watchdog.events import FileSystemEventHandler  # type: ignore
from watchdog.observers import Observer  # type: ignore

geoip_reader = None
GEOIP_DEFAULT_PATH = "/usr/share/GeoIP/GeoLite2-City.mmdb"

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
        mqtt_config: Optional[Dict[str, Any]],
        influxdb_config: Optional[Dict[str, Any]],
        use_geoip: bool = False,
    ) -> None:
        """
        Initialize RuleWatcher instance.

        Args:
            path: Path to the log file to watch.
            rule_file: Path to YAML file with regex rules.
            verbosity: Verbosity level for notifications.
            mqtt_config: Configuration dictionary for MQTT.
            influxdb_config: Optional configuration for InfluxDB.
            use_geoip: Whether to use GeoIP lookups.
        """
        self.path: str = path
        self.rule_file: str = rule_file
        self.verbosity: int = verbosity
        self.mqtt_config: Optional[Dict[str, Any]] = mqtt_config
        self.influxdb_config: Optional[Dict[str, Any]] = influxdb_config
        self.rules_hash: Optional[str] = None
        self.rules: Dict[str, List[re.Pattern]] = {}
        self.use_geoip: bool = use_geoip
        self.recent_matches = deque(maxlen=100)
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
        if not self.mqtt_config:
            logging.error("MQTT config is not set. Cannot send MQTT message.")
            return
        topic = f"{self.mqtt_config['topic_base']}"
        try:
            topic = f"{self.mqtt_config['topic_base']}/{os.path.basename(self.path).replace('.log','')}/{level}"
            payload_dict = {
                "log": self.path,
                "level": level,
                "message": message,
            }

            ip = self.extract_ip(message)
            if ip:
                payload_dict["ip"] = ip
                if self.use_geoip and geoip_reader:
                    try:
                        city = geoip_reader.city(ip)
                        if (
                            city.location
                            and city.location.latitude is not None
                            and city.location.longitude is not None
                        ):
                            payload_dict["geo_lat"] = str(city.location.latitude)
                            payload_dict["geo_lon"] = str(city.location.longitude)
                    except Exception as e:
                        logging.error(f"GeoIP lookup failed for IP {ip}: {e}")

            payload = json.dumps(payload_dict)
            logging.info(f"MQTT SEND: topic={topic}, payload={payload}")
            print(f"MQTT SEND TRIGGERED: {payload}")
            publish.single(
                topic,
                payload=payload,
                hostname=self.mqtt_config["host"],
                port=self.mqtt_config.get("port", 1883),
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
                self.recent_matches.append({"level": level, "line": msg})
                self.send_mqtt(level, msg)
                self.send_influxdb(level, msg)

    def extract_ip(self, line: str) -> Optional[str]:
        """
        Extract an IPv4 or IPv6 address from the log line.

        This implementation **prioritizes explicit IPv4 addresses (optionally with a port)** anywhere in the line
        so that timestamps like "16:59:07" are not mistaken for an IP address. It still looks for contextual
        markers (from, src=, client=, host=) and finally falls back to generic IPv4/IPv6 candidates with
        basic sanity checks to avoid matching time stamps.
        Returns the IP (IPv4 without port) or an IPv6 candidate string, or None if nothing found.
        """
        # 1) Prefer any explicit IPv4 (with optional :port) anywhere in the line — this avoids matching timestamps
        m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?", line)
        if m:
            return m.group(1)

        # 2) Contextual patterns that may include IPs (try to capture IPv4 first inside those contexts)
        contextual = [
            r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b",
            r"\bsrc=((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?",
            r"\bclient=((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?",
            r"\bhost=((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?",
            # bracketed or raw IPv6-ish forms
            r"\[([a-fA-F0-9:]+)\]",
            r"\bfrom\s+([a-fA-F0-9:]+)\b",
        ]
        for pat in contextual:
            mm = re.search(pat, line)
            if mm:
                ip = mm.group(1)
                # If we accidentally captured IPv4 with a port, strip the port
                if ":" in ip and ip.count(".") == 3:
                    ip = ip.split(":")[0]
                return ip

        # 3) If above didn't match, look for any IPv4 later in the line (return first dotted match)
        ipv4s = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", line)
        if ipv4s:
            return ipv4s[0]

        # 4) Try to find IPv6-like candidates but avoid matching pure timestamps like HH:MM:SS
        #    We require either presence of a hex-letter, '::' or at least 3 colons to accept a candidate.
        ipv6_candidates = re.findall(r"[A-Fa-f0-9:]+", line)
        for cand in ipv6_candidates:
            if "::" in cand or re.search(r"[a-fA-F]", cand) or cand.count(":") >= 3:
                # exclude typical timestamps like 16:59:07 or 1:02:03.456
                if not re.fullmatch(r"\d{1,2}:\d{2}:\d{2}(?:\.\d+)?", cand):
                    return cand

        return None

    def send_influxdb(self, level: str, message: str) -> None:
        """
        Send a log event metric to InfluxDB with improved IP extraction.

        Args:
            level: Severity level.
            message: Log message text.
        """
        influx_cfg = self.influxdb_config
        if not influx_cfg:
            return
        try:
            ip = self.extract_ip(message)
            ip_tag = ""
            geo_lat_tag = ""
            geo_lon_tag = ""
            if ip:
                ip_tag = f",ip={ip}"
                logging.debug(f"Extracted IP: {ip}")
                if self.use_geoip and geoip_reader:
                    try:
                        city = geoip_reader.city(ip)
                        if (
                            city.location
                            and city.location.latitude is not None
                            and city.location.longitude is not None
                        ):
                            geo_lat_tag = f",geo_lat={city.location.latitude}"
                            geo_lon_tag = f",geo_lon={city.location.longitude}"
                    except Exception as e:
                        logging.error(f"GeoIP lookup failed for IP {ip}: {e}")
            else:
                logging.info(f"No IP found in line: {message} – sending without IP.")

            line = f"log_event,logfile={os.path.basename(self.path)},level={level}{ip_tag}{geo_lat_tag}{geo_lon_tag} value=1"
            logging.debug(f"Influx line: {line}")
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
                    if self.watcher.mqtt_config:
                        publish.single(
                            f"{self.watcher.mqtt_config.get('topic_base', 'logdetective')}/status",
                            payload=rotate_payload,
                            hostname=self.watcher.mqtt_config["host"],
                            port=self.watcher.mqtt_config.get("port", 1883),
                            auth=(
                                (
                                    self.watcher.mqtt_config.get("username"),
                                    self.watcher.mqtt_config.get("password"),
                                )
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
    use_geoip: bool = config.get("use_geoip", False)
    geoip_path: str = config.get("geoip_path", GEOIP_DEFAULT_PATH)

    # Initialize GeoIP reader if enabled
    global geoip_reader
    if use_geoip:
        try:
            geoip_reader = geoip2.database.Reader(geoip_path)
            logging.info(f"GeoIP lookup enabled using {geoip_path}.")
        except Exception as e:
            geoip_reader = None
            logging.error(f"Failed to load GeoIP database from {geoip_path}: {e}")

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
            log_cfg["path"],
            log_cfg["rule_file"],
            verbosity,
            mqtt_config,
            influxdb_config,
            use_geoip,
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

    def persist_rule_to_file(rule_file: str, level: str, new_rule: str):
        """Append a new rule to the YAML rules file under the given level."""
        try:
            with open(rule_file, "r") as f:
                rules_data = yaml.safe_load(f) or {}
            if level not in rules_data:
                rules_data[level] = []
            if new_rule not in rules_data[level]:
                rules_data[level].append(new_rule)
                with open(rule_file, "w") as f:
                    yaml.dump(rules_data, f, default_flow_style=False)
                print(f"💾 Saved new {level} rule to {rule_file}")
        except Exception as e:
            print(f"⚠️ Failed to write rule to file: {e}")

    def monitor_rulefile_changes(watcher: RuleWatcher):
        last_hash = None
        while True:
            try:
                with open(watcher.rule_file, "rb") as f:
                    data = f.read()
                    current_hash = md5(data).hexdigest()
                    if last_hash and current_hash != last_hash:
                        print("♻️  Rule file updated externally. Reloading...")
                        watcher._load_rules()
                    last_hash = current_hash
            except Exception as e:
                print(f"⚠️ Error watching rule file: {e}")
            time.sleep(3)

    def interactive_cli(watcher: RuleWatcher):
        """Interactive CLI menu for rule management and inspection."""
        disabled_rules = {"critical": [], "suspicious": []}
        while True:
            print("\n[LogDetective Interactive CLI]")
            print("1) Show active rules")
            print("2) Add new critical rule")
            print("3) Add new suspicious rule")
            print("4) Show recent log matches")
            print("5) Exit monitoring")
            print("6) Delete a rule")
            print("7) Disable a rule temporarily (session only)")
            print("8) Restore disabled rule")
            print("9) Edit rule file manually")
            choice = input("Choose option: ").strip()
            if choice == "1":
                print("== Active Rules ==")
                for level in ("critical", "suspicious"):
                    print(f"\n[{level.upper()}]")
                    for rule in watcher.rules.get(level, []):
                        print(" -", rule.pattern)
            elif choice == "2":
                new_rule = input("Enter new critical regex: ").strip()
                try:
                    compiled = re.compile(new_rule)
                    if any(r.pattern == compiled.pattern for r in watcher.rules["critical"]):
                        print("⚠️ Rule already exists.")
                        continue
                    watcher.rules["critical"].append(compiled)
                    print("✅ Added new critical rule.")
                    persist_rule_to_file(watcher.rule_file, "critical", new_rule)
                except re.error as e:
                    print("❌ Invalid regex:", e)
            elif choice == "3":
                new_rule = input("Enter new suspicious regex: ").strip()
                try:
                    compiled = re.compile(new_rule)
                    if any(r.pattern == compiled.pattern for r in watcher.rules["suspicious"]):
                        print("⚠️ Rule already exists.")
                        continue
                    watcher.rules["suspicious"].append(compiled)
                    print("✅ Added new suspicious rule.")
                    persist_rule_to_file(watcher.rule_file, "suspicious", new_rule)
                except re.error as e:
                    print("❌ Invalid regex:", e)
            elif choice == "4":
                print("\n[Recent Log Matches]")
                for entry in list(watcher.recent_matches)[-10:]:
                    print(f"[{entry['level'].upper()}] {entry['line'].strip()}")
            elif choice == "5":
                print("🛑 Exiting monitoring...")
                os.kill(os.getpid(), signal.SIGINT)
                break
            elif choice == "6":
                level = input("Level (critical/suspicious): ").strip().lower()
                if level not in watcher.rules:
                    print("❌ Invalid level.")
                    continue
                for idx, rule in enumerate(watcher.rules[level]):
                    print(f"{idx+1}) {rule.pattern}")
                to_remove = input("Enter number of rule to delete: ").strip()
                try:
                    idx = int(to_remove) - 1
                    pattern_str = watcher.rules[level][idx].pattern
                    watcher.rules[level].pop(idx)
                    print(f"🗑️ Removed rule: {pattern_str}")
                    with open(watcher.rule_file, "r") as f:
                        rules_data = yaml.safe_load(f) or {}
                    rules_data[level] = [r for r in rules_data.get(level, []) if r != pattern_str]
                    with open(watcher.rule_file, "w") as f:
                        yaml.dump(rules_data, f)
                except Exception as e:
                    print("❌ Error removing rule:", e)
            elif choice == "7":
                level = input("Level (critical/suspicious): ").strip().lower()
                if level not in watcher.rules:
                    print("❌ Invalid level.")
                    continue
                for idx, rule in enumerate(watcher.rules[level]):
                    print(f"{idx+1}) {rule.pattern}")
                to_disable = input("Enter number of rule to disable: ").strip()
                try:
                    idx = int(to_disable) - 1
                    disabled = watcher.rules[level].pop(idx)
                    disabled_rules[level].append(disabled)
                    print(f"⛔ Temporarily disabled rule: {disabled.pattern}")
                except Exception as e:
                    print("❌ Error disabling rule:", e)
            else:
                print("Invalid option.")

            if choice == "8":
                level = input("Level (critical/suspicious): ").strip().lower()
                if level not in disabled_rules or not disabled_rules[level]:
                    print("❌ No disabled rules found.")
                    continue
                for idx, rule in enumerate(disabled_rules[level]):
                    print(f"{idx+1}) {rule.pattern}")
                to_restore = input("Enter number of rule to restore: ").strip()
                try:
                    idx = int(to_restore) - 1
                    restored = disabled_rules[level].pop(idx)
                    watcher.rules[level].append(restored)
                    print(f"✅ Restored rule: {restored.pattern}")
                except Exception as e:
                    print("❌ Error restoring rule:", e)

            if choice == "9":
                print(f"Opening rule file: {watcher.rule_file}")
                editor = os.environ.get("EDITOR", "nano")
                os.system(f"{editor} {watcher.rule_file}")

    def cli_interface():
        parser = argparse.ArgumentParser(
            description="LogDetective CLI interface",
            epilog="For full config, omit --logfile/--rules. Interactive mode allows live rule editing.",
        )
        parser.add_argument("--logfile", help="Path to log file to monitor in live or test mode.")
        parser.add_argument("--rules", help="Path to rule YAML file (e.g., rules/ssh.yaml).")
        parser.add_argument(
            "--geoip", action="store_true", help="Enable GeoIP lookup for IP addresses."
        )
        parser.add_argument(
            "--mqtt", action="store_true", help="Enable MQTT output (default config assumed)."
        )
        parser.add_argument(
            "--influx", action="store_true", help="Enable InfluxDB output (default config assumed)."
        )
        parser.add_argument(
            "--test", action="store_true", help="Run once through log without watching."
        )
        parser.add_argument(
            "--verbosity",
            type=int,
            default=1,
            help="Verbosity level: 0=silent, 1=suspicious, 2=all.",
        )
        parser.add_argument(
            "--interactive", action="store_true", help="Enable interactive CLI menu for live mode."
        )
        args = parser.parse_args()

        if not args.logfile or not args.rules:
            print("💡 No CLI arguments or incomplete. Running with full config.\n")
            write_pid()
            start_monitoring()
            return

        mqtt_cfg = {"host": "localhost", "topic_base": "logdetective"} if args.mqtt else None
        influx_cfg = (
            {"host": "localhost", "port": 8086, "database": "logdetective"} if args.influx else None
        )

        write_pid()
        watcher = RuleWatcher(
            args.logfile,
            args.rules,
            args.verbosity,
            mqtt_cfg,
            influx_cfg,
            args.geoip,
        )

        if args.test:
            print(f"[TEST MODE] Scanning {args.logfile} once using {args.rules}")
            with open(args.logfile) as f:
                for line in f:
                    for level, match in watcher.check_line(line):
                        watcher.recent_matches.append({"level": level, "line": match})
                        if mqtt_cfg:
                            watcher.send_mqtt(level, match)
                        if influx_cfg:
                            watcher.send_influxdb(level, match)
                        print(f"[{level.upper()}] {match.strip()}")
        else:
            print(f"🔍 Starting LogDetective in live mode on {args.logfile}")
            if args.interactive:
                threading.Thread(target=interactive_cli, args=(watcher,), daemon=True).start()
                threading.Thread(
                    target=monitor_rulefile_changes, args=(watcher,), daemon=True
                ).start()
            event_handler = LogFileHandler(watcher)
            observer = Observer()
            observer.schedule(event_handler, os.path.dirname(watcher.path), recursive=False)
            observer.start()
            try:
                while running:
                    time.sleep(1)
            finally:
                observer.stop()
                observer.join()
                logging.info("Shutting down log_detective...")

    try:
        cli_interface()
    except SystemExit:
        pass
    except Exception as e:
        logging.error(f"[CLI ERROR] {e}")
        write_pid()
        start_monitoring()

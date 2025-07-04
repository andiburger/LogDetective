# LogDetective

**A lightweight and configurable log monitoring tool that scans multiple log files for suspicious or critical entries and publishes findings to an MQTT broker.**

---

## Features

- Monitor multiple log files with individual rule sets (YAML-based)
- Dynamic rule reloading without restarting the service
- Publish alerts via MQTT with customizable topics per log file
- Supports verbosity levels for detailed logging
- Resource-efficient design for low CPU and memory usage
- Runs natively or in Docker (including Raspberry Pi support)
- PID file management for process control

---

## Table of Contents

- [Installation](#installation)  
- [Configuration](#configuration)  
- [Running](#running)  
- [Docker Deployment](#docker-deployment)  
- [MQTT Integration](#mqtt-integration)  
- [Rules](#rules)  
- [Development & Testing](#development--testing)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Installation

### Requirements

- Python 3.8+  
- [paho-mqtt](https://pypi.org/project/paho-mqtt/)  
- [PyYAML](https://pypi.org/project/PyYAML/)  

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Configuration

Configure your monitored logs and rules in a config.yaml file:

```yaml
logs:
  - path: "/var/log/mumble-server/mumble-server.log"
    rule_file: "rules/mumble.yaml"
    mqtt_topic: "logdetective/mumble"
  - path: "/var/log/auth.log"
    rule_file: "rules/ssh.yaml"
    mqtt_topic: "logdetective/ssh"
  - path: "/var/log/psad/alert"
    rule_file: "rules/psad.yaml"
    mqtt_topic: "logdetective/psad"
  - path: "/var/log/ufw.log"
    rule_file: "rules/ufw.yaml"
    mqtt_topic: "logdetective/ufw"
  - path: "/var/log/fail2ban.log"
    rule_file: "rules/fail2ban.yaml"
    mqtt_topic: "logdetective/fail2ban"

mqtt:
  host: "mqtt.example.com"
  port: 1883
  username: "your_username"
  password: "your_password"
  keepalive: 60
  client_id: "log_detective_client"
  base_topic: "logdetective"
  
logging:
  level: INFO
  file: "/var/log/log_detective.log"

pid_file: "/var/run/log_detective.pid"
```

- logs: List of log files with corresponding rule files and MQTT topics
- mqtt: MQTT broker connection details
- logging: Log file and verbosity level for the script itself
- pid_file: Optional PID file for process management

## Running

Run the monitor with:
```bash
python3 log_detective.py --config /path/to/config.yaml
```

## Docker Deployment

Build the Docker image:
```bash
docker build -t log_detective:latest .
```

Run the container:
```bash
docker run -d \
  --name log_detective \
  --restart unless-stopped \
  -v /var/log:/var/log:ro \
  -v /etc/log_detective/config.yaml:/app/config.yaml:ro \
  -v /etc/log_detective/rules:/app/rules:ro \
  --network host \
  log_detective:latest
```

### Note:
Ensure the container has read access to the log files and rule definitions.
Using --network host allows direct MQTT access on host network.

## MQTT Integration

Log Detective publishes findings as JSON messages to MQTT topics specified in the config.

Example message payload:
```json
{
  "timestamp": "2025-07-04T12:34:56Z",
  "logfile": "/var/log/mumble-server/mumble-server.log",
  "level": "CRITICAL",
  "message": "Rejected connection from 192.168.1.42",
  "matched_rule": "rejected_connection"
}
```

You can subscribe to these topics to integrate alerts into your monitoring dashboards or automation workflows.

## Rules

Rules are YAML files describing regex patterns for critical and suspicious entries.

Example (rules/mumble.yaml):
```yaml
critical:
  - "Rejected connection from <HOST>"
  - "Failed to set priority limits"
suspicious:
  - "Connection closed: Error during SSL handshake"
  - "New connection from <HOST>"
```
Patterns support <HOST> placeholder to match IP addresses.

## Development & Testing
- The code supports dynamic reloading of rules when changed
- Verbosity levels (DEBUG, INFO, WARNING, ERROR) help with debugging and log verbosity
- PID file management supports integration with systemd or other process managers

## License

MIT License
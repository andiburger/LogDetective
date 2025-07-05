import yaml
import re

with open("rules/murmur.yaml") as f:
    rules = yaml.safe_load(f)

print("Loaded rules:", rules)

for level in ("critical", "suspicious"):
    for pattern in rules.get(level, []):
        try:
            regex = re.compile(pattern)
            test_line = "<W>2025-07-03 01:03:34.256 Connection closed: Error during SSL handshake: error:0A000102:SSL routines::unsupported protocol [13]"
            print(f"Testing pattern {pattern}: Match =", bool(regex.search(test_line)))
        except re.error as e:
            print(f"Invalid regex {pattern}: {e}")
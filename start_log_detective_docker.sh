#!/bin/bash

# Start the LogDetective Docker container
docker run -d \
  --name log_detective \
  --restart unless-stopped \
  -v /var/log/mumble-server:/var/log/mumble-server:ro \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  -v /var/log/ufw.log:/var/log/ufw.log:ro \
  -v /var/log/fail2ban.log:/var/log/fail2ban.log:ro \
  -v /minecraft/logs:/minecraft/logs:ro \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v "$(pwd)/rules:/app/rules:ro" \
  --network host \
  log_detective:pi5
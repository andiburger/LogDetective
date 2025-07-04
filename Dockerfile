FROM python:3.13-slim

# Update system packages to address vulnerabilities
RUN apt-get update && apt-get upgrade -y && apt-get clean


WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY log_detective.py ./
COPY config.yml ./
COPY rules/ ./rules/

RUN mkdir -p /var/run /var/log/mumble-server /var/log/psad /var/log/ufw /var/log/fail2ban

VOLUME ["/var/log/mumble-server", "/var/log/psad", "/var/log/ufw", "/var/log/fail2ban"]

CMD ["python", "log_detective.py"]
FROM python:3.12-slim-bookworm

# Update system packages to address vulnerabilities
RUN apt-get update && apt-get upgrade -y && apt-get clean

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY log_detective/ ./log_detective/
COPY rules/ ./rules/

RUN mkdir -p /var/run /var/log/mumble-server /var/log/ufw /var/log/fail2ban

# Create directory for GeoIP database (to be mounted from host)
RUN mkdir -p /usr/share/GeoIP

CMD ["python", "-m", "log_detective.log_detective"]
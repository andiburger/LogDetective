FROM python:3.14-slim

# System-Dependencies für watchdog
RUN apt-get update && apt-get install -y gcc python3-dev libffi-dev && rm -rf /var/lib/apt/lists/*

# Arbeitsverzeichnis
WORKDIR /app

# Python-Requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Skript und Konfig kopieren
COPY log_detective.py .
COPY config.yaml ./config.yaml
COPY rules ./rules

CMD ["python", "log_detective.py"]
# test.Dockerfile
FROM python:3.12-slim-bookworm

WORKDIR /app

COPY requirements.txt requirements-dev.txt /app/
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . /app

CMD ["pytest", "--maxfail=1", "--disable-warnings", "-q"]
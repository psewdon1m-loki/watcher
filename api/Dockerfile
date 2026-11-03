FROM python:3.15-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements.txt \
    && addgroup -S watcher \
    && adduser -S -D -H -G watcher watcher \
    && mkdir -p /data \
    && chown watcher:watcher /data
COPY common /app/common
COPY api/app.py /app/app.py

EXPOSE 8080
USER watcher
CMD ["python", "/app/app.py"]

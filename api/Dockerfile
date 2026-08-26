FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc

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

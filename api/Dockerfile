FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements.txt \
    && addgroup -S watcher \
    && adduser -S -D -H -G watcher watcher \
    && mkdir -p /data \
    && chown watcher:watcher /data
COPY common /app/common
COPY api/app.py /app/app.py

EXPOSE 8080
USER watcher
CMD ["python", "/app/app.py"]

FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc

WORKDIR /app
RUN apk upgrade --no-cache \
    && addgroup -S watcher \
    && adduser -S -D -H -G watcher watcher
COPY web/static /app/static

EXPOSE 8080
USER watcher
CMD ["python", "-m", "http.server", "8080", "--directory", "/app/static"]

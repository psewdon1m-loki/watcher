FROM python:3.15-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

WORKDIR /app
RUN apk upgrade --no-cache \
    && addgroup -S watcher \
    && adduser -S -D -H -G watcher watcher
COPY web/static /app/static

EXPOSE 8080
USER watcher
CMD ["python", "-m", "http.server", "8080", "--directory", "/app/static"]

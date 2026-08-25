FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

WORKDIR /app
RUN addgroup -S watcher \
    && adduser -S -D -H -G watcher watcher
COPY web/static /app/static

EXPOSE 8080
USER watcher
CMD ["python", "-m", "http.server", "8080", "--directory", "/app/static"]

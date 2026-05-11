FROM python:3.12-slim

WORKDIR /app
COPY static /app/static

EXPOSE 8080
CMD ["python", "-m", "http.server", "8080", "--directory", "/app/static"]

# Network Mapper backend — FastAPI + Celery worker image.
# Build context is the repo root so /app contains backend/, scanner/ and matcher/.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# Run migrations, then start the API.
CMD ["sh", "-c", "alembic -c backend/alembic.ini upgrade head && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"]
# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps needed to build weasyprint & semgrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Code Security Analysis Platform"
LABEL org.opencontainers.image.description="Static analysis API with OWASP-aligned findings"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

WORKDIR /app

# Build context is the repo root (set in docker-compose.yml)
COPY backend/app/ ./app/
COPY frontend/ ./frontend/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
# Set to "*" to disable auth in dev; set comma-separated keys in production
ENV SECURITY_API_KEYS=*

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

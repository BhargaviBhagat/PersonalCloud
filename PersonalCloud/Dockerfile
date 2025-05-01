
FROM python:3.9-slim AS builder

WORKDIR /app
COPY requirements.txt .

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libffi-dev \
    libpq-dev \
    netcat-openbsd && \
    pip install --user -r requirements.txt && \
    apt-get remove -y gcc python3-dev libffi-dev libpq-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*


FROM python:3.9-slim AS production


RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app


RUN groupadd -r appuser && \
    useradd -r -g appuser appuser && \
    mkdir -p /app/uploads /app/flask_session && \
    chown -R appuser:appuser /app


COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local


COPY --chown=appuser:appuser . .


RUN pip install --no-cache-dir gunicorn==20.1.0 && \
    chown -R appuser:appuser /app


ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV FLASK_ENV=production
ENV UPLOAD_FOLDER=/app/uploads
ENV FLASK_SESSION_DIR=/app/flask_session


RUN mkdir -p /app/uploads && \
    chown -R appuser:appuser /app/uploads
USER appuser


HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000


CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
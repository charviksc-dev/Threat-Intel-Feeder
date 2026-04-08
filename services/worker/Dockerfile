FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app ./app

# Non-root user
RUN useradd -m -r neev && chown -R neev:neev /app
USER neev

CMD ["celery", "-A", "app.celery_app.celery", "worker", "--loglevel=info", "--concurrency=4"]

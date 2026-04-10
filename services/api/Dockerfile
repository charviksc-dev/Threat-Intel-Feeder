FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app ./app

# Non-root user for security
RUN useradd -m -r neev && chown -R neev:neev /app
USER neev

EXPOSE 8000

# Production: use multiple workers with access logging
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--access-log"]

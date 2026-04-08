"""Celery application configuration with Beat schedule for automatic feed sync."""

from celery import Celery
from celery.schedules import crontab
import os

# Redis as broker and result backend
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

celery = Celery(
    "neev-worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks"],
)

# Celery configuration
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,          # 10 min hard timeout per task
    task_soft_time_limit=540,     # 9 min soft timeout
    worker_max_tasks_per_child=100,  # Prevent memory leaks
    worker_prefetch_multiplier=1,    # Fair distribution
    broker_connection_retry_on_startup=True,
)

# ─── Celery Beat Schedule ──────────────────────────────────────────
# This ensures feeds are automatically ingested on a schedule.
celery.conf.beat_schedule = {
    # Full sync of all threat feeds — every hour
    "sync-all-feeds-hourly": {
        "task": "app.tasks.sync_all_feeds",
        "schedule": crontab(minute=0),  # Every hour at :00
        "options": {"queue": "default"},
    },

    # Free feeds (no API key needed) — every 30 minutes
    "sync-free-feeds": {
        "task": "app.tasks.sync_free_feeds",
        "schedule": crontab(minute="*/30"),
        "options": {"queue": "default"},
    },

    # OTX feed — every 2 hours (rate limit friendly)
    "sync-otx-feed": {
        "task": "app.tasks.ingest_otx_feed",
        "schedule": crontab(minute=15, hour="*/2"),
        "options": {"queue": "default"},
    },

    # VirusTotal feed — every 4 hours (strict rate limits)
    "sync-virustotal-feed": {
        "task": "app.tasks.ingest_virustotal_feed",
        "schedule": crontab(minute=30, hour="*/4"),
        "options": {"queue": "default"},
    },
}

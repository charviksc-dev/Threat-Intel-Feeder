import logging
from datetime import datetime, timezone
from typing import Any

from .celery_app import celery
from .config import settings
from .services.elasticsearch import ElasticIndexer
from .services.cache import create_cache_client
from .services.normalizer import normalize_indicator
from .services.scorer import compute_confidence_score
from .adapters.otx import fetch_otx_indicators
from .adapters.abusech import fetch_abusech_indicators
from .adapters.misp import fetch_misp_indicators
from .adapters.virustotal import fetch_virustotal_indicators
from .adapters.urlhaus import fetch_urlhaus_indicators
from .adapters.threatfox import fetch_threatfox_indicators
from .adapters.feodo_tracker import fetch_feodo_indicators
from .adapters.emerging_threats import fetch_emerging_threats_indicators
from .adapters.openphish import fetch_openphish_indicators
from .adapters.phishtank import fetch_phishtank_indicators
from .adapters.spamhaus import fetch_spamhaus_indicators
from .adapters.hybrid_analysis import fetch_hybrid_analysis_indicators
from .enrichment.virustotal import get_virustotal_report
from .enrichment.geoip import get_geoip_data
from .enrichment.whois import get_whois_data
from .engine.correlator import correlate_indicators
from .engine.scorer import score_batch
from .engine.alerting import process_indicators_for_alerts
from .engine.response import execute_playbooks

logger = logging.getLogger(__name__)

indexer = ElasticIndexer(settings.ELASTICSEARCH_HOST, settings.ELASTICSEARCH_INDEX)
cache = create_cache_client()


def build_document_id(source: str, indicator: str) -> str:
    return f"{source}::{indicator}"


def enrich_document(document: dict[str, Any]) -> dict[str, Any]:
    indicator = document["indicator"]

    try:
        vt_report = get_virustotal_report(indicator, cache)
    except Exception:
        vt_report = {}
    document["metadata"]["virustotal"] = vt_report

    if document["type"] in {"ipv4", "ipv6"}:
        try:
            document["geo"] = get_geoip_data(indicator)
        except Exception:
            pass

    if document["type"] in {"domain", "url"}:
        try:
            document["metadata"]["whois"] = get_whois_data(indicator)
        except Exception:
            pass

    document["metadata"]["feed_count"] = document["metadata"].get("feed_count", 1) + 1
    score = compute_confidence_score(
        indicator,
        {
            "feed_count": document["metadata"]["feed_count"],
            "vt_score": vt_report.get("vt_score"),
            "first_seen": document.get("first_seen"),
            "tags": document.get("tags", []),
        },
    )
    document["confidence_score"] = score
    document["updated_at"] = datetime.utcnow().isoformat()
    return document


def index_payload(raw: dict[str, Any]) -> None:
    try:
        normalized = normalize_indicator(raw)
        normalized = enrich_document(normalized)
        document_id = build_document_id(normalized["source"], normalized["indicator"])
        indexer.upsert(document_id, normalized)

        # --- Execute SOAR runbooks on updated document ---
        execute_playbooks(normalized)

    except Exception as e:
        logger.warning("Failed to index indicator %s: %s", raw.get("indicator"), e)


def ingest_feed(name: str, fetcher, source_name: str) -> dict[str, Any]:
    """Generic feed ingestion with error handling."""
    logger.info("Starting %s ingestion", name)
    try:
        items = fetcher()
    except Exception as e:
        logger.error("Failed to fetch %s feed: %s", name, e)
        report_feed_health(source_name, 0, False, str(e))
        return {"source": source_name, "count": 0, "error": str(e)}

    indexed = 0
    for raw in items:
        index_payload(raw)
        indexed += 1

    logger.info("Ingested %d indicators from %s", indexed, name)
    report_feed_health(source_name, indexed, True, None)
    return {"source": source_name, "count": indexed}


def report_feed_health(
    source_name: str, count: int, success: bool, error: str | None
) -> None:
    """Report feed health metrics to the API."""
    try:
        import requests

        api_url = settings.API_BASE_URL or "http://localhost:8000"
        requests.post(
            f"{api_url}/api/v1/feeds/health",
            json={
                "feed_name": source_name,
                "ioc_count": count,
                "success": success,
                "error_message": error,
            },
            timeout=5,
        )
    except Exception as e:
        logger.warning("Failed to report feed health for %s: %s", source_name, e)


# ── Original adapters ──────────────────────────────────────────────


@celery.task(name="worker.ingest.otx")
def ingest_otx_feed() -> dict[str, Any]:
    return ingest_feed("OTX", fetch_otx_indicators, "otx")


@celery.task(name="worker.ingest.abusech")
def ingest_abusech_feed() -> dict[str, Any]:
    return ingest_feed("Abuse.ch", fetch_abusech_indicators, "abusech")


@celery.task(name="worker.ingest.misp")
def ingest_misp_feed() -> dict[str, Any]:
    return ingest_feed("MISP", fetch_misp_indicators, "misp")


# ── New adapters ───────────────────────────────────────────────────


@celery.task(name="worker.ingest.virustotal")
def ingest_virustotal_feed() -> dict[str, Any]:
    return ingest_feed("VirusTotal", fetch_virustotal_indicators, "virustotal")


@celery.task(name="worker.ingest.urlhaus")
def ingest_urlhaus_feed() -> dict[str, Any]:
    return ingest_feed("URLhaus", fetch_urlhaus_indicators, "urlhaus")


@celery.task(name="worker.ingest.threatfox")
def ingest_threatfox_feed() -> dict[str, Any]:
    return ingest_feed("ThreatFox", fetch_threatfox_indicators, "threatfox")


@celery.task(name="worker.ingest.feodo")
def ingest_feodo_feed() -> dict[str, Any]:
    return ingest_feed("Feodo Tracker", fetch_feodo_indicators, "feodo-tracker")


@celery.task(name="worker.ingest.emerging_threats")
def ingest_emerging_threats_feed() -> dict[str, Any]:
    return ingest_feed(
        "Emerging Threats", fetch_emerging_threats_indicators, "emerging-threats"
    )


@celery.task(name="worker.ingest.openphish")
def ingest_openphish_feed() -> dict[str, Any]:
    return ingest_feed("OpenPhish", fetch_openphish_indicators, "openphish")


@celery.task(name="worker.ingest.phishtank")
def ingest_phishtank_feed() -> dict[str, Any]:
    return ingest_feed("PhishTank", fetch_phishtank_indicators, "phishtank")


@celery.task(name="worker.ingest.spamhaus")
def ingest_spamhaus_feed() -> dict[str, Any]:
    return ingest_feed("Spamhaus", fetch_spamhaus_indicators, "spamhaus")


@celery.task(name="worker.ingest.hybrid_analysis")
def ingest_hybrid_analysis_feed() -> dict[str, Any]:
    return ingest_feed(
        "Hybrid Analysis", fetch_hybrid_analysis_indicators, "hybrid_analysis"
    )


# ── Sync all feeds ─────────────────────────────────────────────────


def _collect_all_indicators() -> list[dict[str, Any]]:
    """Fetch all indicators from every feed without indexing individually."""
    all_indicators: list[dict[str, Any]] = []

    fetchers = [
        ("OTX", fetch_otx_indicators),
        ("Abuse.ch", fetch_abusech_indicators),
        ("MISP", fetch_misp_indicators),
        ("VirusTotal", fetch_virustotal_indicators),
        ("URLhaus", fetch_urlhaus_indicators),
        ("ThreatFox", fetch_threatfox_indicators),
        ("Feodo Tracker", fetch_feodo_indicators),
        ("Emerging Threats", fetch_emerging_threats_indicators),
        ("OpenPhish", fetch_openphish_indicators),
        ("PhishTank", fetch_phishtank_indicators),
        ("Spamhaus", fetch_spamhaus_indicators),
        ("Hybrid Analysis", fetch_hybrid_analysis_indicators),
    ]

    for name, fetcher in fetchers:
        try:
            items = fetcher()
            logger.info("Collected %d raw indicators from %s", len(items), name)
            all_indicators.extend(items)
        except Exception as e:
            logger.error("Failed to fetch %s feed: %s", name, e)

    return all_indicators


@celery.task(name="worker.sync.all")
def sync_all_feeds() -> dict[str, Any]:
    """Orchestrate parallel feed ingestion with post-processing pipeline."""
    from celery import group

    # Fire all feeds in parallel using Celery group
    feed_tasks = group(
        ingest_otx_feed.s(),
        ingest_abusech_feed.s(),
        ingest_misp_feed.s(),
        ingest_virustotal_feed.s(),
        ingest_urlhaus_feed.s(),
        ingest_threatfox_feed.s(),
        ingest_feodo_feed.s(),
        ingest_emerging_threats_feed.s(),
        ingest_openphish_feed.s(),
        ingest_phishtank_feed.s(),
        ingest_spamhaus_feed.s(),
        ingest_hybrid_analysis_feed.s(),
    )
    result = feed_tasks.apply_async()
    result.get(timeout=540)  # Wait up to 9 minutes

    # Post-ingestion pipeline: Correlate → Score → Alert
    raw_indicators = _collect_all_indicators()
    correlated = correlate_indicators(raw_indicators)
    scored = score_batch(correlated)
    alerts = process_indicators_for_alerts(scored)

    for ind in scored:
        document_id = build_document_id(ind.get("source", "unknown"), ind["indicator"])
        try:
            indexer.upsert(document_id, ind)
        except Exception as e:
            logger.warning(
                "Failed to index scored indicator %s: %s", ind.get("indicator"), e
            )

    if alerts:
        logger.info("Generated %d alerts during sync", len(alerts))

    return {
        "correlated_count": len(correlated),
        "scored_count": len(scored),
        "alert_count": len(alerts),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@celery.task(name="worker.sync.free")
def sync_free_feeds() -> dict[str, Any]:
    """Sync only feeds that don't require API keys (safe for frequent scheduling)."""
    from celery import group

    free_feed_tasks = group(
        ingest_abusech_feed.s(),
        ingest_urlhaus_feed.s(),
        ingest_threatfox_feed.s(),
        ingest_feodo_feed.s(),
        ingest_openphish_feed.s(),
        ingest_phishtank_feed.s(),
        ingest_spamhaus_feed.s(),
    )
    result = free_feed_tasks.apply_async()
    result.get(timeout=300)

    return {
        "status": "ok",
        "feeds_synced": 7,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

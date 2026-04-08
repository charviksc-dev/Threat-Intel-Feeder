"""SIEM Integration API Routes

Endpoints for receiving logs from and pushing data to SIEM tools.
"""

import json
import logging
from datetime import datetime

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch, get_postgres_pool
from ..config import settings
from .auth import get_current_user
from ..utils.security import verify_webhook_token
from ..integrations.wazuh import (
    parse_wazuh_alert,
    extract_wazuh_alert_metadata,
    push_to_thehive,
)
from ..integrations.suricata import (
    parse_eve_event,
    extract_alert_metadata,
    parse_eve_batch,
)
from ..integrations.zeek import parse_zeek_json_event
from ..integrations.firewall import (
    generate_ip_blocklist,
    generate_domain_blocklist,
    format_blocklist,
    format_as_json,
)
from ..integrations.misp_sync import push_indicators_to_misp, pull_misp_events
from ..integrations.thehive import (
    push_alert,
    convert_indicator_to_observable,
)
from ..integrations.webhook import parse_json_webhook, parse_cef_log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["siem-integrations"])


async def require_integration_auth(
    request: Request,
    x_webhook_token: str | None = Header(None, alias="X-Webhook-Token"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    pool=Depends(get_postgres_pool),
):
    """Dependency that allows either X-Webhook-Token OR a valid user session."""
    # 1. Try Webhook Token authentication
    if verify_webhook_token(x_webhook_token):
        return {"auth": "webhook"}

    # 2. Try User Session (Bearer Token) for UI tests
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            user = await get_current_user(token, pool)
            if user:
                return {"auth": "user", "user": user}
            else:
                logger.warning("Integration auth: User not found for email in token")
        except Exception as e:
            logger.error("Integration auth session check failed: %s", e)
    else:
        logger.debug("Integration auth: No valid Authorization header found")

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: Missing valid integration token or user session",
    )


# ═══════════════════════════════════════════════════════════════════
# WAZUH INTEGRATION
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/wazuh/webhook")
async def wazuh_webhook(
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    pool=Depends(get_postgres_pool),
    _auth=Depends(require_integration_auth),
):
    """Receive alerts from Wazuh via Active Response webhook.

    Configure Wazuh to POST alerts to this endpoint:
    In Wazuh ossec.conf:
    <integration>
      <name>custom-api</name>
      <hook_url>http://YOUR_HOST:8000/api/v1/integrations/wazuh/webhook</hook_url>
      <alert_format>json</alert_format>
    </integration>
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Handle both single alert and array of alerts
    alerts = body if isinstance(body, list) else [body]

    indicators_indexed = 0
    alerts_stored = 0

    for alert in alerts:
        # Extract IOCs and index them
        indicators = parse_wazuh_alert(alert)
        for ind in indicators:
            doc_id = f"wazuh::{ind['indicator']}"
            try:
                await es.update(
                    index=settings.ELASTICSEARCH_INDEX,
                    id=doc_id,
                    body={"doc": ind, "doc_as_upsert": True},
                )
                indicators_indexed += 1
            except Exception as e:
                logger.warning("Failed to index Wazuh IOC: %s", e)

        # Store alert metadata
        alert_meta = extract_wazuh_alert_metadata(alert)
        if pool:
            try:
                async with pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, NOW()) ON CONFLICT (alert_id) DO NOTHING",
                        alert_meta["alert_id"],
                        alert_meta["source"],
                        alert_meta["severity"],
                        alert_meta["category"],
                        json.dumps(alert_meta["payload"]),
                    )
                    alerts_stored += 1
            except Exception as e:
                logger.warning("Failed to store Wazuh alert: %s", e)

        # Push to TheHive if configured
        if settings.THEHIVE_URL and alert.get("rule", {}).get("level", 0) >= 7:
            push_to_thehive(alert_meta)

    return {
        "status": "ok",
        "alerts_received": len(alerts),
        "indicators_indexed": indicators_indexed,
        "alerts_stored": alerts_stored,
    }


# ═══════════════════════════════════════════════════════════════════
# SURICATA INTEGRATION
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/suricata/eve")
async def suricata_eve_webhook(
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    pool=Depends(get_postgres_pool),
    _auth=Depends(require_integration_auth),
):
    """Receive Suricata EVE JSON events via HTTP output.

    Configure Suricata to send EVE logs to this endpoint.
    In suricata.yaml:
    outputs:
      - eve-log:
          enabled: yes
          filetype: regular
          filename: eve.json
          types:
            - alert
            - dns
            - tls
            - http
            - fileinfo

    Then use a log shipper (Filebeat, Vector, or curl) to POST each
    JSON line to this endpoint.
    """
    try:
        raw_body = await request.body()
        if b"connection_check" in raw_body:
            # Insert a dummy alert for visibility during testing
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, NOW()) ON CONFLICT (alert_id) DO NOTHING",
                    f"suricata-test-{datetime.utcnow().timestamp()}",
                    "suricata",
                    "low",
                    "test",
                    json.dumps({"status": "integration verified", "test_event": "connection_check"}),
                )
            return {"status": "connected", "source": "suricata"}

        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    events = body if isinstance(body, list) else [body]

    indicators_indexed = 0
    alerts_stored = 0

    for event in events:
        indicators = parse_eve_event(event)
        for ind in indicators:
            doc_id = f"suricata::{ind['indicator']}"
            try:
                await es.update(
                    index=settings.ELASTICSEARCH_INDEX,
                    id=doc_id,
                    body={"doc": ind, "doc_as_upsert": True},
                )
                indicators_indexed += 1
            except Exception:
                pass

        # Store Suricata alerts in PostgreSQL
        if event.get("event_type") == "alert":
            alert_meta = extract_alert_metadata(event)
            if pool:
                try:
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, NOW()) ON CONFLICT (alert_id) DO NOTHING",
                            alert_meta["alert_id"],
                            alert_meta["source"],
                            alert_meta["severity"],
                            alert_meta["category"],
                            json.dumps(alert_meta["payload"]),
                        )
                        alerts_stored += 1
                except Exception as e:
                    logger.warning("Failed to store Suricata alert: %s", e)

    return {
        "status": "ok",
        "events_received": len(events),
        "indicators_indexed": indicators_indexed,
        "alerts_stored": alerts_stored,
    }


@router.post("/integrations/suricata/eve-batch")
async def suricata_eve_batch(
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _auth=Depends(require_integration_auth),
):
    """Receive multiple Suricata EVE JSON lines (newline-delimited).

    Send raw EVE JSON file content (one JSON object per line).
    """
    body = await request.body()
    text = body.decode("utf-8", errors="replace")

    indicators = parse_eve_batch(text)
    indexed = 0
    for ind in indicators:
        doc_id = f"suricata::{ind['indicator']}"
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=doc_id,
                body={"doc": ind, "doc_as_upsert": True},
            )
            indexed += 1
        except Exception:
            pass

    return {"status": "ok", "indicators_indexed": indexed}


# ═══════════════════════════════════════════════════════════════════
# ZEEK INTEGRATION
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/zeek/{log_type}")
async def zeek_webhook(
    log_type: str,
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    pool=Depends(get_postgres_pool),
    _auth=Depends(require_integration_auth),
):
    """Receive Zeek log events via HTTP.

    Supported log_types: conn, dns, http, ssl, files, notice, x509

    Configure Zeek to stream JSON logs to this endpoint using:
    @load policy/tuning/json-logs.zeek

    Then use a log shipper to POST events to:
    POST /api/v1/integrations/zeek/dns
    POST /api/v1/integrations/zeek/http
    POST /api/v1/integrations/zeek/conn
    etc.
    """
    valid_types = {"conn", "dns", "http", "ssl", "files", "notice", "x509"}
    if log_type not in valid_types:
        raise HTTPException(
            status_code=400, detail=f"Invalid log_type. Must be one of: {valid_types}"
        )

    try:
        raw_body = await request.body()
        if b"connection_check" in raw_body:
            # Insert a dummy alert for visibility
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, NOW()) ON CONFLICT (alert_id) DO NOTHING",
                    f"zeek-test-{datetime.utcnow().timestamp()}",
                    "zeek",
                    "low",
                    "test",
                    json.dumps({"status": "integration verified", "log_type": log_type}),
                )
            return {"status": "connected", "source": "zeek", "log_type": log_type}

        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    events = body if isinstance(body, list) else [body]

    indicators_indexed = 0
    alerts_stored = 0
    for event in events:
        indicators = parse_zeek_json_event(event, log_type)
        for ind in indicators:
            doc_id = f"zeek::{ind['indicator']}"
            try:
                await es.update(
                    index=settings.ELASTICSEARCH_INDEX,
                    id=doc_id,
                    body={"doc": ind, "doc_as_upsert": True},
                )
                indicators_indexed += 1
            except Exception:
                pass

        # Store Zeek notices as alerts
        if log_type == "notice" or (isinstance(event, dict) and event.get("note")):
            try:
                alert_id = f"zeek-{log_type}-{datetime.utcnow().timestamp()}"
                async with pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, NOW()) ON CONFLICT (alert_id) DO NOTHING",
                        alert_id,
                        "zeek",
                        "medium",
                        event.get("note", "Zeek Notice"),
                        json.dumps(event),
                    )
                    alerts_stored += 1
            except Exception as e:
                logger.warning("Failed to store Zeek alert: %s", e)

    return {
        "status": "ok",
        "log_type": log_type,
        "events_received": len(events),
        "indicators_indexed": indicators_indexed,
        "alerts_stored": alerts_stored,
    }


# ═══════════════════════════════════════════════════════════════════
# GENERIC WEBHOOK RECEIVER
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/webhook/{source_name}")
async def generic_webhook(
    source_name: str,
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Generic webhook receiver for any JSON source.

    Send JSON payloads from any tool:
    POST /api/v1/integrations/webhook/my-tool

    Automatically extracts IPs, domains, URLs, and hashes.
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    events = body if isinstance(body, list) else [body]

    indicators_indexed = 0
    for event in events:
        indicators = parse_json_webhook(event, source_name)
        for ind in indicators:
            doc_id = f"{source_name}::{ind['indicator']}"
            try:
                await es.update(
                    index=settings.ELASTICSEARCH_INDEX,
                    id=doc_id,
                    body={"doc": ind, "doc_as_upsert": True},
                )
                indicators_indexed += 1
            except Exception:
                pass

    return {
        "status": "ok",
        "source": source_name,
        "events_received": len(events),
        "indicators_indexed": indicators_indexed,
    }


@router.post("/integrations/cef/{source_name}")
async def cef_webhook(
    source_name: str,
    request: Request,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Receive CEF (Common Event Format) logs.

    Send CEF-formatted log lines:
    POST /api/v1/integrations/cef/arcsight

    Body: raw CEF text, one event per line.
    """
    body = await request.body()
    text = body.decode("utf-8", errors="replace")

    all_indicators = []
    for line in text.strip().split("\n"):
        if line.strip():
            indicators = parse_cef_log(line, source_name)
            all_indicators.extend(indicators)

    indexed = 0
    for ind in all_indicators:
        doc_id = f"{source_name}::{ind['indicator']}"
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=doc_id,
                body={"doc": ind, "doc_as_upsert": True},
            )
            indexed += 1
        except Exception:
            pass

    return {"status": "ok", "indicators_indexed": indexed}


# ═══════════════════════════════════════════════════════════════════
# FIREWALL BLOCKLIST EXPORT
# ═══════════════════════════════════════════════════════════════════


@router.get("/blocklist/ips", response_class=PlainTextResponse)
async def get_ip_blocklist(
    format: str = Query(
        "plain", description="Output format: plain, iptables, nftables, pf"
    ),
    min_score: float = Query(0.0, description="Minimum confidence score"),
    source: str | None = Query(None, description="Filter by source"),
    threat_type: str | None = Query(None, description="Filter by threat type"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Get IP blocklist for firewall ingestion.

    Fetch this endpoint from your firewall script:
    curl http://localhost:8000/api/v1/blocklist/ips?format=iptables > /etc/blocklist.rules
    curl http://localhost:8000/api/v1/blocklist/ips?format=plain > /etc/blocklist.txt

    Supports: plain, iptables, nftables, pf
    """
    body = {
        "query": {"bool": {"filter": [{"terms": {"type": ["ipv4", "ipv6"]}}]}},
        "size": 10000,
        "_source": ["indicator", "type", "confidence_score", "source", "threat_types"],
    }

    if min_score > 0:
        body["query"]["bool"]["filter"].append(
            {"range": {"confidence_score": {"gte": min_score}}}
        )
    if source:
        body["query"]["bool"]["filter"].append({"term": {"source": source}})
    if threat_type:
        body["query"]["bool"]["filter"].append({"term": {"threat_types": threat_type}})

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicators = [hit["_source"] for hit in response["hits"]["hits"]]

    ips = generate_ip_blocklist(indicators, min_score)
    return format_blocklist(ips, output_format=format, indicators=indicators)


@router.get("/blocklist/domains", response_class=PlainTextResponse)
async def get_domain_blocklist(
    format: str = Query("hosts", description="Output format: hosts, unbound, zeek, wazuh, plain"),
    min_score: float = Query(0.0, description="Minimum confidence score"),
    source: str | None = Query(None, description="Filter by source"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Get domain blocklist for DNS sinkholing.

    curl http://localhost:8000/api/v1/blocklist/domains?format=hosts > /etc/hosts.blocklist
    curl http://localhost:8000/api/v1/blocklist/domains?format=zeek > /opt/zeek/share/zeek/site/intel/domains.intel
    """
    body = {
        "query": {"bool": {"filter": [{"term": {"type": "domain"}}]}},
        "size": 10000,
        "_source": ["indicator", "type", "confidence_score", "source", "threat_types"],
    }

    if min_score > 0:
        body["query"]["bool"]["filter"].append(
            {"range": {"confidence_score": {"gte": min_score}}}
        )
    if source:
        body["query"]["bool"]["filter"].append({"term": {"source": source}})

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicators = [hit["_source"] for hit in response["hits"]["hits"]]

    domains = generate_domain_blocklist(indicators, min_score)
    return format_blocklist([], domains, output_format=format, indicators=indicators)


@router.get("/blocklist/all")
async def get_full_blocklist_json(
    min_score: float = Query(0.0, description="Minimum confidence score"),
    source: str | None = Query(None, description="Filter by source"),
    threat_type: str | None = Query(None, description="Filter by threat type"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Get full blocklist as JSON for API consumption."""
    body = {
        "query": {
            "bool": {"filter": [{"terms": {"type": ["ipv4", "ipv6", "domain", "url"]}}]}
        },
        "size": 10000,
    }

    if min_score > 0:
        body["query"]["bool"]["filter"].append(
            {"range": {"confidence_score": {"gte": min_score}}}
        )
    if source:
        body["query"]["bool"]["filter"].append({"term": {"source": source}})
    if threat_type:
        body["query"]["bool"]["filter"].append({"term": {"threat_types": threat_type}})

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicators = [hit["_source"] for hit in response["hits"]["hits"]]

    return JSONResponse(content=json.loads(format_as_json(indicators)))


# ═══════════════════════════════════════════════════════════════════
# MISP BIDIRECTIONAL SYNC
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/misp/push")
async def push_to_misp(
    min_score: float = Query(50.0, description="Minimum confidence score to push"),
    limit: int = Query(100, description="Maximum indicators to push"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: object = Depends(get_current_user),
):
    """Push high-confidence IOCs to MISP.

    Creates a new MISP event with indicators from Neev TIP.
    """
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        raise HTTPException(status_code=503, detail="MISP not configured")

    body = {
        "query": {"range": {"confidence_score": {"gte": min_score}}},
        "size": limit,
        "sort": [{"confidence_score": "desc"}],
    }

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicators = [hit["_source"] for hit in response["hits"]["hits"]]

    if not indicators:
        return {"status": "ok", "message": "No indicators above threshold", "pushed": 0}

    result = push_indicators_to_misp(indicators)
    if result:
        return {"status": "ok", "pushed": len(indicators), "misp_event": result}
    else:
        raise HTTPException(status_code=500, detail="Failed to push to MISP")


@router.get("/integrations/misp/pull")
async def pull_from_misp(
    days: int = Query(7, description="Pull events from last N days"),
    limit: int = Query(100, description="Maximum indicators to pull"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: object = Depends(get_current_user),
):
    """Pull IOCs from MISP and index them."""
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        raise HTTPException(status_code=503, detail="MISP not configured")

    indicators = pull_misp_events(last_days=days, limit=limit)

    indexed = 0
    for ind in indicators:
        doc_id = f"misp::{ind['indicator']}"
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=doc_id,
                body={"doc": ind, "doc_as_upsert": True},
            )
            indexed += 1
        except Exception:
            pass

    return {"status": "ok", "pulled": len(indicators), "indexed": indexed}


# ═══════════════════════════════════════════════════════════════════
# THEHIVE INTEGRATION
# ═══════════════════════════════════════════════════════════════════


@router.post("/integrations/thehive/push")
async def push_to_thehive_endpoint(
    title: str = Query(..., description="Alert title"),
    source: str = Query("neev", description="Source name"),
    severity: int = Query(2, description="1=low, 2=med, 3=high, 4=critical"),
    indicator_ids: list[str] = Query(
        [], description="Indicator IDs to attach as observables"
    ),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: object = Depends(get_current_user),
):
    """Push an alert to TheHive with indicators as observables."""
    if not settings.THEHIVE_URL:
        raise HTTPException(status_code=503, detail="TheHive not configured")

    observables = []
    for iid in indicator_ids:
        try:
            doc = await es.get(index=settings.ELASTICSEARCH_INDEX, id=iid)
            obs = convert_indicator_to_observable(doc["_source"])
            observables.append(obs)
        except Exception:
            pass

    # Safely get source_ref — avoid unbound 'iid' when indicator_ids is empty
    source_ref = f"neev-{indicator_ids[-1]}" if indicator_ids else f"neev-alert-{hash(title)}"

    result = push_alert(
        title=title,
        description=f"Alert from Neev TIP with {len(observables)} observables",
        source=source,
        source_ref=source_ref,
        severity=severity,
        observables=observables,
    )

    if result:
        return {"status": "ok", "thehive_alert": result}
    else:
        raise HTTPException(status_code=500, detail="Failed to push to TheHive")


# ═══════════════════════════════════════════════════════════════════
# FIREWALL IMPORT (add blocked IPs from your firewall to Neev)
# ═══════════════════════════════════════════════════════════════════


@router.post("/blocklist/import")
async def import_blocklist(
    request: Request,
    source: str = Query("firewall", description="Source label for imported IPs"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Import IPs/domains from your firewall blocklist into Neev.

    POST a list of IPs or domains (one per line):
    curl -X POST "http://localhost:8000/api/v1/blocklist/import?source=my-firewall" \
      --data-binary @blocked_ips.txt

    Or POST JSON:
    {"ips": ["1.2.3.4", "5.6.7.8"], "domains": ["evil.com"]}
    """
    content_type = request.headers.get("content-type", "")

    indicators = []

    if "json" in content_type:
        try:
            body = await request.json()
            for ip in body.get("ips", []):
                indicators.append(
                    {
                        "indicator": ip,
                        "type": "ipv4",
                        "source": source,
                        "threat_types": ["blocked"],
                        "tags": [f"source:{source}", "firewall-blocked"],
                        "metadata": {"imported_from": "firewall"},
                    }
                )
            for domain in body.get("domains", []):
                indicators.append(
                    {
                        "indicator": domain,
                        "type": "domain",
                        "source": source,
                        "threat_types": ["blocked"],
                        "tags": [f"source:{source}", "firewall-blocked"],
                        "metadata": {"imported_from": "firewall"},
                    }
                )
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON")
    else:
        # Plain text, one entry per line
        body = await request.body()
        text = body.decode("utf-8", errors="replace")
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Auto-detect type
            parts = line.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                ind_type = "ipv4"
            else:
                ind_type = "domain"

            indicators.append(
                {
                    "indicator": line,
                    "type": ind_type,
                    "source": source,
                    "threat_types": ["blocked"],
                    "tags": [f"source:{source}", "firewall-blocked"],
                    "metadata": {"imported_from": "firewall"},
                }
            )

    indexed = 0
    for ind in indicators:
        doc_id = f"{source}::{ind['indicator']}"
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=doc_id,
                body={"doc": ind, "doc_as_upsert": True},
            )
            indexed += 1
        except Exception:
            pass

    return {"status": "ok", "imported": indexed, "source": source}

# ═══════════════════════════════════════════════════════════════════
# FEED SYNC TRIGGER
# ═══════════════════════════════════════════════════════════════════

class SyncRequest(BaseModel):
    task_name: str

@router.post("/feeds/sync")
async def trigger_feed_sync(req: SyncRequest, user: dict = Depends(get_current_user)):
    """Trigger a celery background job to sync threat feeds."""
    if not req.task_name.startswith("worker."):
        raise HTTPException(status_code=400, detail="Invalid task name")
    
    import os
    from celery import Celery
    celery_app = Celery("app", broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"))
    celery_app.send_task(req.task_name)
    
    return {"status": "ok", "message": f"Successfully triggered background sync for {req.task_name}"}

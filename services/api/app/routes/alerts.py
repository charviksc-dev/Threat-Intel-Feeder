import json
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from asyncpg import Pool

from ..dependencies import get_postgres_pool
from .auth import get_current_token_payload, get_current_user

router = APIRouter(prefix="/api/v1", tags=["alerts"])

SUMMARY_COLUMNS = """
    a.id,
    a.alert_id,
    a.source,
    a.severity,
    a.category,
    a.status,
    a.assigned_to,
    a.received_at,
    a.acknowledged_at,
    a.resolved_at,
    a.resolution_type,
    a.false_positive_reason,
    a.asset_hostname,
    a.asset_owner,
    a.asset_criticality,
    a.asset_network_zone,
    a.sensor_source,
    a.sensor_rule_id
"""


class AlertPayload(BaseModel):
    alert_id: str
    source: str
    severity: str | None = None
    category: str | None = None
    payload: dict


class AlertStatusUpdate(BaseModel):
    status: str
    resolution_type: Optional[str] = None
    reason: Optional[str] = None


class AlertAssign(BaseModel):
    user_id: int


class AlertNoteCreate(BaseModel):
    note: str


async def log_alert_audit(
    pool: Pool, alert_id: str, action: str, actor_id: int, details: dict = None
):
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alert_audit (alert_id, action, actor_id, details) VALUES ($1, $2, $3, $4)",
            alert_id,
            action,
            actor_id,
            json.dumps(details or {}),
        )


async def ensure_alert_exists(conn, alert_id: str) -> None:
    exists = await conn.fetchval("SELECT 1 FROM alerts WHERE alert_id = $1", alert_id)
    if not exists:
        raise HTTPException(status_code=404, detail="Alert not found")


def _coerce_payload(raw_payload: Any) -> dict:
    if isinstance(raw_payload, dict):
        return raw_payload
    if isinstance(raw_payload, str):
        try:
            parsed = json.loads(raw_payload)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _extract_candidate_iocs(payload: dict) -> dict:
    iocs = {"ip": None, "domain": None, "url": None, "hash": None}

    ip_fields = [
        "src_ip",
        "dst_ip",
        "source_ip",
        "dest_ip",
        "client_ip",
        "remote_ip",
    ]
    domain_fields = ["domain", "hostname", "dns_query", "fqdn"]
    url_fields = ["url", "uri", "request_url"]
    hash_fields = ["sha256", "sha1", "md5", "hash", "file_hash"]

    for field in ip_fields:
        if payload.get(field):
            iocs["ip"] = str(payload[field])
            break
    for field in domain_fields:
        if payload.get(field):
            iocs["domain"] = str(payload[field])
            break
    for field in url_fields:
        if payload.get(field):
            iocs["url"] = str(payload[field])
            break
    for field in hash_fields:
        if payload.get(field):
            iocs["hash"] = str(payload[field])
            break

    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    if not iocs["ip"] and agent.get("ip"):
        iocs["ip"] = str(agent["ip"])
    if not iocs["domain"] and agent.get("name"):
        iocs["domain"] = str(agent["name"])
    return iocs


def _nested_get(payload: dict, *path: str) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _shorten(value: Any, limit: int = 120) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _append_unique(target: List[str], message: str) -> None:
    if message and message not in target:
        target.append(message)


def _build_alert_analysis(alert: dict) -> dict:
    payload = _coerce_payload(alert.get("payload"))
    iocs = _extract_candidate_iocs(payload)
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    mitre_ids = mitre.get("id") if isinstance(mitre.get("id"), list) else []
    mitre_tactics = mitre.get("tactic") if isinstance(mitre.get("tactic"), list) else []
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}

    severity = (alert.get("severity") or "medium").lower()
    source = alert.get("source") or "unknown"
    category = alert.get("category") or "uncategorized activity"
    host = agent.get("name") or alert.get("asset_hostname") or "unknown host"
    status = alert.get("status") or "new"
    rule_id = str(rule.get("id") or "").strip()
    rule_description = str(rule.get("description") or "").strip()
    explicit_ip_fields = [
        "src_ip",
        "dst_ip",
        "source_ip",
        "dest_ip",
        "client_ip",
        "remote_ip",
    ]
    explicit_domain_fields = ["domain", "dns_query", "fqdn"]
    explicit_url_fields = ["url", "uri", "request_url"]
    explicit_ip_ioc = next(
        (
            str(payload[field]).strip()
            for field in explicit_ip_fields
            if payload.get(field) is not None and str(payload.get(field)).strip()
        ),
        None,
    )
    has_explicit_domain_ioc = any(
        payload.get(field) is not None and str(payload.get(field)).strip()
        for field in explicit_domain_fields
    )
    has_explicit_url_ioc = any(
        payload.get(field) is not None and str(payload.get(field)).strip()
        for field in explicit_url_fields
    )

    # Common Wazuh/Sysmon/Windows event context (best-effort extraction)
    win_event_data = _nested_get(payload, "data", "win", "eventdata")
    if not isinstance(win_event_data, dict):
        win_event_data = {}
    process_image = (
        win_event_data.get("Image")
        or win_event_data.get("ProcessName")
        or payload.get("process_name")
        or payload.get("process")
    )
    parent_image = win_event_data.get("ParentImage") or win_event_data.get(
        "ParentProcessName"
    )
    command_line = (
        win_event_data.get("CommandLine")
        or payload.get("command")
        or payload.get("cmdline")
    )
    target_filename = (
        win_event_data.get("TargetFilename")
        or payload.get("file")
        or payload.get("filepath")
    )
    destination_port = (
        win_event_data.get("DestinationPort")
        or payload.get("dst_port")
        or payload.get("dest_port")
    )
    destination_ip = win_event_data.get("DestinationIp") or explicit_ip_ioc
    user_name = (
        win_event_data.get("User")
        or payload.get("username")
        or payload.get("user")
        or _nested_get(payload, "data", "srcuser")
    )
    win_event_id = (
        _nested_get(payload, "data", "win", "system", "eventID")
        or _nested_get(payload, "win", "system", "eventID")
        or payload.get("event_id")
    )

    normalized_text_parts = [
        str(source or ""),
        str(category or ""),
        str(rule_description or ""),
        " ".join(mitre_ids),
        " ".join(mitre_tactics),
        str(process_image or ""),
        str(parent_image or ""),
        str(command_line or ""),
        str(target_filename or ""),
        str(
            payload.get("decoder", {}).get("name")
            if isinstance(payload.get("decoder"), dict)
            else ""
        ),
    ]
    normalized_text = " ".join(normalized_text_parts).lower()

    is_process_activity = bool(
        process_image
        or command_line
        or str(win_event_id) in {"1", "4688"}
        or "process" in normalized_text
        or "sysmon" in normalized_text
    )
    is_network_activity = bool(
        destination_ip
        or has_explicit_domain_ioc
        or has_explicit_url_ioc
        or destination_port
        or str(win_event_id) in {"3", "5156"}
        or "network" in normalized_text
        or "connection" in normalized_text
        or "dns" in normalized_text
    )
    is_auth_activity = bool(
        user_name
        and (
            "logon" in normalized_text
            or "login" in normalized_text
            or "authentication" in normalized_text
            or "credential" in normalized_text
            or str(win_event_id) in {"4624", "4625", "4776"}
        )
    )
    is_file_activity = bool(
        target_filename
        or iocs["hash"]
        or "file" in normalized_text
        or "registry" in normalized_text
    )
    is_powershell_or_script = any(
        token in normalized_text
        for token in [
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "encodedcommand",
        ]
    )
    is_c2_like = any(
        token in normalized_text
        for token in [
            "command and control",
            "c2",
            "beacon",
            "t1071",
            "t1105",
            "web service",
            "ingress tool transfer",
        ]
    )
    is_persistence_like = any(
        token in normalized_text
        for token in [
            "persistence",
            "scheduled task",
            "run key",
            "startup",
            "service creation",
            "autorun",
            "registry run",
        ]
    )

    risk_label = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(severity, "Medium")

    confidence_pct = {"critical": 95, "high": 80, "medium": 65, "low": 45}.get(
        severity, 65
    )

    findings = [
        f"Alert source: {source}; category: {category}.",
        f"Current workflow status: {status}.",
        f"Observed host: {host}.",
    ]
    if rule_id:
        findings.append(f"Detection rule id: {rule_id}.")
    if rule_description:
        findings.append(f"Rule description: {_shorten(rule_description, 180)}.")
    if iocs["ip"]:
        findings.append(f"Primary IP artifact: {iocs['ip']}.")
    if iocs["domain"]:
        findings.append(f"Primary domain/host artifact: {iocs['domain']}.")
    if iocs["url"]:
        findings.append(f"URL artifact: {iocs['url']}.")
    if iocs["hash"]:
        findings.append(f"File/hash artifact: {iocs['hash']}.")
    if process_image:
        findings.append(f"Process image: {_shorten(process_image)}.")
    if parent_image:
        findings.append(f"Parent process: {_shorten(parent_image)}.")
    if command_line:
        findings.append(f"Command line: {_shorten(command_line, 160)}.")
    if user_name:
        findings.append(f"User context: {_shorten(user_name)}.")
    if target_filename:
        findings.append(f"File target: {_shorten(target_filename)}.")
    if destination_port:
        findings.append(f"Destination port observed: {destination_port}.")
    if win_event_id:
        findings.append(f"Windows event id: {win_event_id}.")
    if mitre_ids:
        findings.append(f"MITRE techniques: {', '.join(mitre_ids[:4])}.")
    if mitre_tactics:
        findings.append(f"Likely tactics: {', '.join(mitre_tactics[:3])}.")

    recommendations: List[str] = []

    if status in {"new", "assigned"}:
        _append_unique(
            recommendations,
            "Acknowledge this alert and assign a primary analyst to avoid triage delay.",
        )

    _append_unique(
        recommendations,
        "Confirm with asset owner whether this behavior is expected for the host/user context.",
    )

    if is_process_activity:
        process_label = _shorten(
            process_image or command_line or "the observed process"
        )
        _append_unique(
            recommendations,
            f"Validate parent-child process lineage and execution context for {process_label}.",
        )
        _append_unique(
            recommendations,
            "Review process creation telemetry around this event (+/-15 minutes) for chained execution.",
        )

    if is_powershell_or_script:
        _append_unique(
            recommendations,
            "Inspect PowerShell/script content for encoded or obfuscated commands and capture the decoded payload.",
        )

    if is_network_activity:
        if destination_ip:
            _append_unique(
                recommendations,
                f"Check reputation and internal communication baseline for destination {destination_ip}.",
            )
        if destination_port:
            _append_unique(
                recommendations,
                f"Validate whether outbound traffic to port {destination_port} is approved for this asset.",
            )
        _append_unique(
            recommendations,
            "Review DNS/HTTP/TLS telemetry for repeated callbacks or beacon-like intervals.",
        )

    if is_auth_activity:
        _append_unique(
            recommendations,
            "Correlate authentication events for this account across DC/endpoints to detect lateral movement.",
        )
        _append_unique(
            recommendations,
            "If authentication is suspicious, force credential reset and review recent privileged activity.",
        )

    if is_file_activity:
        if target_filename:
            _append_unique(
                recommendations,
                f"Inspect file or registry artifact changes related to {_shorten(target_filename)}.",
            )
        if iocs["hash"]:
            _append_unique(
                recommendations,
                "Submit the observed hash to sandbox/intel sources and quarantine matching artifacts if malicious.",
            )

    if is_persistence_like:
        _append_unique(
            recommendations,
            "Hunt for persistence artifacts (scheduled tasks, autoruns, services, run keys) on the host.",
        )

    if is_c2_like:
        _append_unique(
            recommendations,
            "Prioritize containment: block suspected C2 destination and capture memory/network evidence.",
        )

    if mitre_ids:
        _append_unique(
            recommendations,
            f"Use MITRE techniques ({', '.join(mitre_ids[:3])}) to drive targeted threat hunting across similar assets.",
        )

    _append_unique(
        recommendations,
        "Correlate nearby alerts from the same host, user, and IOC in the last 30 minutes.",
    )
    _append_unique(
        recommendations,
        "Document final triage decision and rationale in analyst notes for auditability.",
    )

    if severity in {"critical", "high"}:
        _append_unique(
            recommendations,
            "Escalate to incident response immediately if business impact or active compromise indicators are confirmed.",
        )
    elif severity == "low":
        _append_unique(
            recommendations,
            "If no additional suspicious context is found, downgrade confidence and continue monitoring.",
        )

    summary_details: List[str] = []
    if rule_description:
        summary_details.append(f"Rule trigger: {_shorten(rule_description, 100)}")
    if process_image:
        summary_details.append(f"Process: {_shorten(process_image, 80)}")
    if destination_ip:
        summary_details.append(f"Destination: {destination_ip}")
    if user_name:
        summary_details.append(f"User: {_shorten(user_name, 60)}")
    detail_suffix = ""
    if summary_details:
        detail_suffix = " " + "; ".join(summary_details[:3]) + "."

    return {
        "headline": f"{risk_label} {source.upper()} alert affecting {host}",
        "plain_language": (
            f"This event indicates {category} from {source}. "
            f"Current risk is {risk_label.lower()} (confidence ~{confidence_pct}%)."
            f"{detail_suffix}"
        ),
        "risk_level": risk_label,
        "confidence_pct": confidence_pct,
        "key_findings": findings,
        "recommended_actions": recommendations,
        "mitre": {"techniques": mitre_ids, "tactics": mitre_tactics},
        "ioc_candidates": iocs,
    }


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
async def ingest_alert(
    payload: AlertPayload,
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (alert_id) DO NOTHING",
            payload.alert_id,
            payload.source,
            payload.severity,
            payload.category,
            json.dumps(payload.payload),
            datetime.utcnow(),
        )
    return {"status": "accepted", "alert_id": payload.alert_id}


@router.get("/alerts")
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    status_filter: str = Query(None, alias="status"),
    severity: str = Query(None),
    include_payload: bool = Query(False),
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> List[dict]:
    columns = SUMMARY_COLUMNS
    if include_payload:
        columns += ",\n    a.payload"

    query = f"""
        SELECT {columns}, u.full_name as assignee_name
        FROM alerts a
        LEFT JOIN users u ON a.assigned_to = u.id 
        WHERE 1=1
    """
    params = []
    param_idx = 1

    if status_filter:
        query += f" AND a.status = ${param_idx}"
        params.append(status_filter)
        param_idx += 1

    if severity:
        query += f" AND a.severity = ${param_idx}"
        params.append(severity)
        param_idx += 1

    query += f" ORDER BY a.received_at DESC LIMIT ${param_idx}"
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    return [dict(row) for row in rows]


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    include_payload: bool = Query(True),
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    columns = SUMMARY_COLUMNS
    if include_payload:
        columns += ",\n    a.payload"

    query = f"""
        SELECT {columns}, u.full_name as assignee_name
        FROM alerts a
        LEFT JOIN users u ON a.assigned_to = u.id
        WHERE a.alert_id = $1
        LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, alert_id)

    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return dict(row)


@router.get("/alerts/{alert_id}/analysis")
async def analyze_alert(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.*, u.full_name as assignee_name
            FROM alerts a
            LEFT JOIN users u ON a.assigned_to = u.id
            WHERE a.alert_id = $1
            LIMIT 1
            """,
            alert_id,
        )

    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _build_alert_analysis(dict(row))


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET status = 'acknowledged', acknowledged_at = $1, assigned_to = COALESCE(assigned_to, $2) WHERE alert_id = $3",
            datetime.utcnow(),
            current_user.id,
            alert_id,
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")

    await log_alert_audit(pool, alert_id, "acknowledged", current_user.id)
    return {"status": "success", "message": "Alert acknowledged"}


@router.post("/alerts/{alert_id}/assign")
async def assign_alert(
    alert_id: str,
    payload: AlertAssign,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET assigned_to = $1, status = CASE WHEN status = 'new' THEN 'assigned' ELSE status END WHERE alert_id = $2",
            payload.user_id,
            alert_id,
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")

        # Track assignment history
        await conn.execute(
            "INSERT INTO alert_assignments (alert_id, assignee_id, assigned_by) VALUES ($1, $2, $3)",
            alert_id,
            payload.user_id,
            current_user.id,
        )

    await log_alert_audit(
        pool, alert_id, "assigned", current_user.id, {"assignee_id": payload.user_id}
    )
    return {"status": "success", "message": "Alert assigned"}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    payload: AlertStatusUpdate,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET status = $1, resolved_at = $2, resolution_type = $3, false_positive_reason = $4 WHERE alert_id = $5",
            payload.status,
            datetime.utcnow(),
            payload.resolution_type,
            payload.reason,
            alert_id,
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")

    await log_alert_audit(
        pool,
        alert_id,
        "resolved",
        current_user.id,
        {"status": payload.status, "type": payload.resolution_type},
    )
    return {"status": "success", "message": f"Alert {payload.status}"}


@router.delete("/alerts/{alert_id}")
async def delete_alert(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    if current_user.role not in {"admin", "soc_manager"}:
        raise HTTPException(
            status_code=403, detail="Only admins and SOC managers can delete alerts"
        )

    async with pool.acquire() as conn:
        async with conn.transaction():
            existing = await conn.fetchval(
                "SELECT 1 FROM alerts WHERE alert_id = $1", alert_id
            )
            if not existing:
                raise HTTPException(status_code=404, detail="Alert not found")

            await conn.execute(
                "INSERT INTO alert_audit (alert_id, action, actor_id, details) VALUES ($1, $2, $3, $4)",
                alert_id,
                "deleted",
                current_user.id,
                json.dumps({"deleted_by_role": current_user.role}),
            )
            await conn.execute("DELETE FROM alert_notes WHERE alert_id = $1", alert_id)
            await conn.execute(
                "DELETE FROM alert_assignments WHERE alert_id = $1", alert_id
            )
            await conn.execute("DELETE FROM alerts WHERE alert_id = $1", alert_id)

    return {"status": "success", "message": "Alert deleted"}


@router.post("/alerts/{alert_id}/notes")
async def add_alert_note(
    alert_id: str,
    payload: AlertNoteCreate,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        await ensure_alert_exists(conn, alert_id)
        await conn.execute(
            "INSERT INTO alert_notes (alert_id, author_id, note) VALUES ($1, $2, $3)",
            alert_id,
            current_user.id,
            payload.note,
        )
    return {"status": "success", "message": "Note added"}


@router.get("/alerts/{alert_id}/notes")
async def get_alert_notes(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        await ensure_alert_exists(conn, alert_id)
        rows = await conn.fetch(
            "SELECT n.*, u.full_name as author_name FROM alert_notes n JOIN users u ON n.author_id = u.id WHERE alert_id = $1 ORDER BY created_at ASC",
            alert_id,
        )
    return [dict(row) for row in rows]


@router.get("/alerts/{alert_id}/audit")
async def get_alert_audit(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    async with pool.acquire() as conn:
        await ensure_alert_exists(conn, alert_id)
        rows = await conn.fetch(
            "SELECT a.*, u.full_name as actor_name FROM alert_audit a LEFT JOIN users u ON a.actor_id = u.id WHERE alert_id = $1 ORDER BY created_at DESC",
            alert_id,
        )
    return [dict(row) for row in rows]


@router.get("/users/analysts")
async def list_analysts(
    pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)
):
    """List all analysts for assignment dropdown."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, email, full_name, role FROM users WHERE role IN ('analyst', 'admin', 'soc_manager') AND is_active = TRUE ORDER BY full_name"
        )
    return [dict(row) for row in rows]


@router.post("/alerts/{alert_id}/thehive")
async def push_alert_to_thehive(
    alert_id: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    """Push an alert to TheHive as a case."""
    from ..integrations.thehive import push_alert

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", alert_id)

    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = dict(row)

    # Map severity to TheHive format (1=low, 2=medium, 3=high, 4=critical)
    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = severity_map.get(alert.get("severity", "medium"), 2)

    # Extract IOCs from payload
    observables = []
    payload = alert.get("payload", {})
    if isinstance(payload, dict):
        # Try to extract common IOC fields
        for field in ["src_ip", "dst_ip", "source_ip", "dest_ip"]:
            if payload.get(field):
                observables.append(
                    {"dataType": "ip", "data": str(payload[field]), "ioc": True}
                )
        for field in ["domain", "hostname"]:
            if payload.get(field):
                observables.append(
                    {"dataType": "domain", "data": str(payload[field]), "ioc": True}
                )
        for field in ["url", "uri"]:
            if payload.get(field):
                observables.append(
                    {"dataType": "url", "data": str(payload[field]), "ioc": True}
                )
        for field in ["file_hash", "hash", "md5", "sha1", "sha256"]:
            if payload.get(field):
                observables.append(
                    {"dataType": "hash", "data": str(payload[field]), "ioc": True}
                )

    title = f"{alert.get('source', 'Alert')}: {alert.get('category', 'Security Event')}"
    description = f"""# Alert Details

**Alert ID:** {alert_id}
**Source:** {alert.get("source")}
**Severity:** {alert.get("severity", "medium")}
**Category:** {alert.get("category", "N/A")}
**Received:** {alert.get("received_at")}

## Raw Payload
```
{json.dumps(alert.get("payload", {}), indent=2)}
```
"""

    result = push_alert(
        title=title,
        description=description,
        source=alert.get("source", "neev"),
        source_ref=alert_id,
        severity=severity,
        tags=[alert.get("severity", "medium"), alert.get("category", "")],
        observables=observables if observables else None,
    )

    if result:
        await log_alert_audit(
            pool,
            alert_id,
            "pushed_to_thehive",
            current_user.id,
            {"thehive_id": result.get("id")},
        )
        return {"status": "success", "thehive_id": result.get("id")}
    else:
        raise HTTPException(
            status_code=500, detail="Failed to push to TheHive - not configured"
        )


@router.post("/alerts/{alert_id}/containment")
async def trigger_containment(
    alert_id: str,
    action: str = "block_ip",
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user),
):
    """Trigger containment action (block IP, isolate host, etc.)."""
    from datetime import datetime, timezone

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", alert_id)

    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = dict(row)
    payload = alert.get("payload", {})

    # Extract IOC to block
    ioc_to_block = None
    if isinstance(payload, dict):
        # Try common IP field names
        for field in [
            "src_ip",
            "dst_ip",
            "source_ip",
            "dest_ip",
            "client_ip",
            "remote_ip",
        ]:
            if payload.get(field):
                ioc_to_block = str(payload[field])
                break

    if not ioc_to_block:
        raise HTTPException(
            status_code=400, detail="No IP found in alert payload to block"
        )

    # Update alert with containment status
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE alerts SET 
                containment_status = 'in_progress',
                containment_action = $1,
                containment_action_by = $2,
                containment_action_at = $3
            WHERE alert_id = $4""",
            action,
            current_user.id,
            datetime.now(timezone.utc),
            alert_id,
        )

    await log_alert_audit(
        pool,
        alert_id,
        "containment_triggered",
        current_user.id,
        {"action": action, "ioc": ioc_to_block},
    )

    # TODO: Integrate with actual firewall APIs (Wazuh, Cloudflare, AWS WAF, etc.)

    return {
        "status": "success",
        "action": action,
        "ioc": ioc_to_block,
        "message": f"Containment action '{action}' triggered for {ioc_to_block}",
    }


# ── SOAR Playbook Routes ─────────────────────────────────────────────────


@router.get("/soar/playbooks")
async def list_playbooks(
    current_user=Depends(get_current_user),
):
    """List available SOAR playbooks."""
    from ..integrations.thehive import get_available_playbooks

    return get_available_playbooks()


@router.post("/soar/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    case_id: str | None = None,
    observables: list[str] | None = None,
    current_user=Depends(get_current_user),
):
    """Execute a SOAR playbook."""
    from ..integrations.thehive import execute_playbook as run_playbook

    if current_user.role not in {"admin", "soc_manager", "analyst"}:
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to execute playbooks"
        )

    result = run_playbook(playbook_id, case_id, observables)

    await log_alert_audit(
        pool,
        case_id or "playbook",
        "playbook_executed",
        current_user.id,
        {"playbook_id": playbook_id, "result": result},
    )

    return result


@router.get("/soar/cases")
async def sync_thehive_cases(
    limit: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
):
    """Sync cases from TheHive for bidirectional status."""
    from ..integrations.thehive import sync_all_cases

    if current_user.role not in {"admin", "soc_manager", "analyst", "viewer"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return sync_all_cases(limit)


@router.get("/soar/cases/{case_id}/status")
async def get_case_status(
    case_id: str,
    current_user=Depends(get_current_user),
):
    """Get case status from TheHive for bidirectional sync."""
    from ..integrations.thehive import sync_case_status

    if current_user.role not in {"admin", "soc_manager", "analyst", "viewer"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return sync_case_status(case_id)


# ── Cortex Analyzer Routes ───────────────────────────────────────────────


@router.get("/soar/cortex/analyzers")
async def list_cortex_analyzers(
    current_user=Depends(get_current_user),
):
    """List available Cortex analyzers."""
    from ..integrations.thehive import get_cortex_analyzers

    if current_user.role not in {"admin", "soc_manager", "analyst", "viewer"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return get_cortex_analyzers()


@router.post("/soar/cortex/analyze")
async def run_cortex_analysis(
    analyzer_id: str,
    observable_type: str,
    observable_value: str,
    current_user=Depends(get_current_user),
):
    """Run a Cortex analyzer on an observable."""
    from ..integrations.thehive import run_cortex_analyzer

    if current_user.role not in {"admin", "soc_manager", "analyst"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return run_cortex_analyzer(analyzer_id, observable_type, observable_value)


@router.get("/soar/cortex/job/{job_id}")
async def get_cortex_result(
    job_id: str,
    current_user=Depends(get_current_user),
):
    """Get Cortex analysis result."""
    from ..integrations.thehive import get_cortex_job_result

    if current_user.role not in {"admin", "soc_manager", "analyst", "viewer"}:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return get_cortex_job_result(job_id)


# ── Webhook DLQ Routes ──────────────────────────────────────────────────


@router.get("/soar/webhooks/failed")
async def get_failed_webhooks(
    current_user=Depends(get_current_user),
):
    """Get failed webhooks from DLQ."""
    from ..integrations.thehive import get_failed_webhooks

    if current_user.role not in {"admin", "soc_manager"}:
        raise HTTPException(status_code=403, detail="Admin only")

    return get_failed_webhooks()


@router.post("/soar/webhooks/retry")
async def retry_webhooks(
    current_user=Depends(get_current_user),
):
    """Retry failed webhooks from DLQ."""
    from ..integrations.thehive import retry_failed_webhooks

    if current_user.role not in {"admin", "soc_manager"}:
        raise HTTPException(status_code=403, detail="Admin only")

    return retry_failed_webhooks()

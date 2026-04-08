"""Webhook Receiver - Generic Live Log Ingestion

Receives live logs from any source via webhooks:
- Syslog (via syslog-ng or rsyslog HTTP output)
- Custom applications
- Cloud services (AWS CloudTrail, Azure, GCP)
- Third-party security tools

Supports multiple input formats:
1. JSON (standard)
2. CEF (Common Event Format)
3. LEEF (Log Event Extended Format)
4. Syslog (BSD/RFC5424)
5. Raw text with regex extraction
"""

import json
import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# ── Generic JSON webhook ────────────────────────────────────────────


def parse_json_webhook(
    payload: dict[str, Any], source: str = "webhook"
) -> list[dict[str, Any]]:
    """Parse a generic JSON webhook payload.

    Supports common field names for IOC extraction.
    """
    indicators = []
    timestamp = (
        payload.get("timestamp")
        or payload.get("time")
        or payload.get("@timestamp")
        or payload.get("event_time")
        or datetime.utcnow().isoformat()
    )

    # IP fields
    for field in [
        "src_ip",
        "source_ip",
        "src",
        "srcAddr",
        "client_ip",
        "remote_addr",
        "ip",
        "ip_address",
    ]:
        ip = payload.get(field)
        if ip and _is_ip(ip):
            indicators.append(
                {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": source,
                    "first_seen": str(timestamp),
                    "threat_types": [payload.get("event_type", "webhook")],
                    "tags": [f"source:{source}"],
                    "metadata": payload,
                }
            )
            break

    for field in ["dst_ip", "dest_ip", "dst", "dstAddr", "server_ip", "destination"]:
        ip = payload.get(field)
        if (
            ip and _is_ip(ip) and ip != indicators[-1]["indicator"]
            if indicators
            else True
        ):
            indicators.append(
                {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": source,
                    "first_seen": str(timestamp),
                    "threat_types": ["destination"],
                    "tags": [f"source:{source}"],
                    "metadata": payload,
                }
            )
            break

    # Domain fields
    for field in ["domain", "hostname", "host", "fqdn", "server_name"]:
        domain = payload.get(field)
        if domain and _is_domain(domain):
            indicators.append(
                {
                    "indicator": domain,
                    "type": "domain",
                    "source": source,
                    "first_seen": str(timestamp),
                    "threat_types": [payload.get("event_type", "webhook")],
                    "tags": [f"source:{source}"],
                    "metadata": payload,
                }
            )
            break

    # URL fields
    for field in ["url", "request_url", "uri", "request_uri"]:
        url = payload.get(field)
        if url and isinstance(url, str) and url.startswith("http"):
            indicators.append(
                {
                    "indicator": url,
                    "type": "url",
                    "source": source,
                    "first_seen": str(timestamp),
                    "threat_types": [payload.get("event_type", "webhook")],
                    "tags": [f"source:{source}"],
                    "metadata": payload,
                }
            )
            break

    # Hash fields
    for field, hash_type in [
        ("md5", "hash"),
        ("sha256", "hash"),
        ("sha1", "hash"),
        ("file_hash", "hash"),
    ]:
        hash_val = payload.get(field)
        if hash_val and len(hash_val) in (32, 40, 64):
            indicators.append(
                {
                    "indicator": hash_val,
                    "type": "hash",
                    "source": source,
                    "first_seen": str(timestamp),
                    "threat_types": [payload.get("event_type", "file")],
                    "tags": [f"source:{source}", field],
                    "metadata": payload,
                }
            )

    return indicators


# ── CEF (Common Event Format) parser ────────────────────────────────


CEF_PATTERN = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
)


def parse_cef_log(cef_line: str, source: str = "cef") -> list[dict[str, Any]]:
    """Parse a CEF (Common Event Format) log line.

    CEF format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
    """
    match = CEF_PATTERN.match(cef_line.strip())
    if not match:
        return []

    (version, vendor, product, device_version, sig_id, name, severity, extensions) = (
        match.groups()
    )

    # Parse key=value pairs from extensions
    ext_data = {}
    for kv in re.findall(r"(\w+)=(.*?)(?:\s+(?=\w+=)|$)", extensions):
        ext_data[kv[0]] = kv[1]

    indicators = []
    timestamp = (
        ext_data.get("rt") or ext_data.get("end") or datetime.utcnow().isoformat()
    )

    # Extract IPs
    src_ip = ext_data.get("src") or ext_data.get("dvc")
    if src_ip and _is_ip(src_ip):
        indicators.append(
            {
                "indicator": src_ip,
                "type": "ipv4",
                "source": source,
                "first_seen": str(timestamp),
                "threat_types": [name],
                "tags": [f"severity:{severity}", f"product:{product}"],
                "metadata": {
                    "cef_vendor": vendor,
                    "cef_product": product,
                    "cef_name": name,
                    "cef_severity": severity,
                    "extensions": ext_data,
                },
            }
        )

    dst_ip = ext_data.get("dst")
    if dst_ip and _is_ip(dst_ip):
        indicators.append(
            {
                "indicator": dst_ip,
                "type": "ipv4",
                "source": source,
                "first_seen": str(timestamp),
                "threat_types": ["destination"],
                "tags": [f"product:{product}"],
                "metadata": ext_data,
            }
        )

    # Extract domains
    domain = ext_data.get("dhost") or ext_data.get("shost")
    if domain and _is_domain(domain):
        indicators.append(
            {
                "indicator": domain,
                "type": "domain",
                "source": source,
                "first_seen": str(timestamp),
                "threat_types": [name],
                "tags": [f"product:{product}"],
                "metadata": ext_data,
            }
        )

    return indicators


# ── Syslog parser ────────────────────────────────────────────────────


SYSLOG_PATTERN = re.compile(
    r"^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
)


def parse_syslog_line(line: str, source: str = "syslog") -> list[dict[str, Any]]:
    """Parse a syslog line (RFC5424 format)."""
    match = SYSLOG_PATTERN.match(line.strip())
    if not match:
        return []

    pri, version, timestamp, hostname, app, procid, msgid, msg = match.groups()

    indicators = []
    # Extract IPs from message using regex
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    found_ips = ip_pattern.findall(msg)

    for ip in found_ips:
        if _is_ip(ip):
            indicators.append(
                {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": source,
                    "first_seen": timestamp,
                    "threat_types": ["syslog-extracted"],
                    "tags": [f"app:{app}", f"host:{hostname}"],
                    "metadata": {
                        "syslog_app": app,
                        "syslog_host": hostname,
                        "syslog_proc": procid,
                        "syslog_msg": msg,
                    },
                }
            )

    return indicators


# ── Helpers ──────────────────────────────────────────────────────────


def _is_ip(value: str) -> bool:
    try:
        parts = value.split(".")
        return len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        )
    except (ValueError, AttributeError):
        return False


def _is_domain(value: str) -> bool:
    return (
        isinstance(value, str)
        and "." in value
        and not _is_ip(value)
        and not value.startswith("http")
    )

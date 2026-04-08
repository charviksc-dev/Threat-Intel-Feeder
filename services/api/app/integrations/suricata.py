"""Suricata IDS/IPS Integration

Parses Suricata EVE JSON logs to extract:
- Alert signatures and ET rules
- Source/Destination IPs
- DNS queries
- TLS SNI (Server Name Indication)
- HTTP host headers
- File hashes (from fileinfo)
- JA3/JA3S fingerprints

Can receive logs via:
1. Suricata's built-in HTTP output (EVE to HTTP)
2. File-based reading (EVE JSON file)
3. Syslog (parsed from syslog JSON)
"""

import json
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# Suricata event types that contain IOCs
IOC_EVENT_TYPES = {"alert", "dns", "tls", "http", "fileinfo", "flow"}


def parse_eve_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a single Suricata EVE JSON event and extract IOCs.

    EVE format:
    {
        "timestamp": "2024-01-01T00:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "src_port": 12345,
        "dest_ip": "5.6.7.8",
        "dest_port": 80,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024249,
            "rev": 4,
            "signature": "ET MALWARE Win32/Ransomware",
            "category": "A Network Trojan was detected",
            "severity": 1
        }
    }
    """
    indicators = []
    event_type = event.get("event_type", "")
    timestamp = event.get("timestamp")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")

    if event_type == "alert":
        alert = event.get("alert", {})
        sig_id = str(alert.get("signature_id", ""))
        sig_name = alert.get("signature", "")
        category = alert.get("category", "")
        severity = alert.get("severity", 3)

        threat_types = []
        sig_lower = sig_name.lower()
        if any(k in sig_lower for k in ["malware", "trojan", "ransomware"]):
            threat_types.append("malware")
        if any(k in sig_lower for k in ["scan", "brute", "bruteforce"]):
            threat_types.append("bruteforce")
        if any(k in sig_lower for k in ["c2", "command", "control"]):
            threat_types.append("c2")
        if any(k in sig_lower for k in ["phish", "credential"]):
            threat_types.append("phishing")
        if any(k in sig_lower for k in ["exploit", "overflow", "injection"]):
            threat_types.append("exploit")
        if not threat_types:
            threat_types.append("ids-alert")

        severity_label = {1: "high", 2: "medium", 3: "low"}.get(severity, "low")

        # Source IP (attacker)
        if src_ip:
            indicators.append(
                {
                    "indicator": src_ip,
                    "type": "ipv4",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": threat_types,
                    "tags": [f"sig:{sig_id}", f"severity:{severity_label}", category],
                    "metadata": {
                        "suricata_gid": alert.get("gid"),
                        "suricata_sid": sig_id,
                        "suricata_signature": sig_name,
                        "suricata_category": category,
                        "suricata_severity": severity,
                        "dest_ip": dest_ip,
                        "dest_port": event.get("dest_port"),
                        "proto": event.get("proto"),
                    },
                }
            )

        # Extract ET rule IOCs from signature
        if "ET INFO" in sig_name or "ETPRO" in sig_name:
            # Try to extract domain/IP from signature text
            parts = sig_name.split()
            for part in parts:
                if "." in part and not part.startswith("ET"):
                    if _is_ip(part):
                        indicators.append(
                            {
                                "indicator": part,
                                "type": "ipv4",
                                "source": "suricata",
                                "first_seen": timestamp,
                                "threat_types": threat_types,
                                "tags": [f"sig:{sig_id}", "extracted"],
                                "metadata": {"suricata_signature": sig_name},
                            }
                        )
                    elif _is_domain(part):
                        indicators.append(
                            {
                                "indicator": part,
                                "type": "domain",
                                "source": "suricata",
                                "first_seen": timestamp,
                                "threat_types": threat_types,
                                "tags": [f"sig:{sig_id}", "extracted"],
                                "metadata": {"suricata_signature": sig_name},
                            }
                        )

    elif event_type == "dns":
        dns = event.get("dns", {})
        query = dns.get("query", {})
        if isinstance(query, list):
            query = query[0] if query else {}
        domain = query.get("rrname") if isinstance(query, dict) else None
        if not domain:
            domain = dns.get("rrname")
        if domain and domain != ".":
            indicators.append(
                {
                    "indicator": domain,
                    "type": "domain",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["dns-query"],
                    "tags": ["suricata:dns"],
                    "metadata": {
                        "dns_type": query.get("rrtype")
                        if isinstance(query, dict)
                        else None,
                        "src_ip": src_ip,
                    },
                }
            )

    elif event_type == "tls":
        tls = event.get("tls", {})
        sni = tls.get("sni")
        ja3 = tls.get("ja3", {}).get("hash")
        ja3s = tls.get("ja3s", {}).get("hash")

        if sni:
            indicators.append(
                {
                    "indicator": sni,
                    "type": "domain",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["tls-sni"],
                    "tags": ["suricata:tls", "sni"],
                    "metadata": {
                        "ja3": ja3,
                        "ja3s": ja3s,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                    },
                }
            )

        if ja3:
            indicators.append(
                {
                    "indicator": ja3,
                    "type": "hash",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["ja3-fingerprint"],
                    "tags": ["suricata:tls", "ja3"],
                    "metadata": {"sni": sni, "src_ip": src_ip},
                }
            )

    elif event_type == "http":
        http = event.get("http", {})
        hostname = http.get("hostname")
        url = http.get("url")
        if hostname:
            indicators.append(
                {
                    "indicator": hostname,
                    "type": "domain",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["http-host"],
                    "tags": ["suricata:http"],
                    "metadata": {
                        "url": url,
                        "http_method": http.get("http_method"),
                        "http_user_agent": http.get("http_user_agent"),
                        "src_ip": src_ip,
                    },
                }
            )

    elif event_type == "fileinfo":
        fileinfo = event.get("fileinfo", {})
        md5 = fileinfo.get("md5")
        sha256 = fileinfo.get("sha256")
        filename = fileinfo.get("filename")

        if md5:
            indicators.append(
                {
                    "indicator": md5,
                    "type": "hash",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["file-hash"],
                    "tags": ["suricata:fileinfo", "md5"],
                    "metadata": {
                        "sha256": sha256,
                        "filename": filename,
                        "size": fileinfo.get("size"),
                        "src_ip": src_ip,
                    },
                }
            )

        if sha256:
            indicators.append(
                {
                    "indicator": sha256,
                    "type": "hash",
                    "source": "suricata",
                    "first_seen": timestamp,
                    "threat_types": ["file-hash"],
                    "tags": ["suricata:fileinfo", "sha256"],
                    "metadata": {
                        "md5": md5,
                        "filename": filename,
                        "size": fileinfo.get("size"),
                        "src_ip": src_ip,
                    },
                }
            )

    return indicators


def parse_eve_batch(eve_lines: str) -> list[dict[str, Any]]:
    """Parse multiple EVE JSON lines (from file or stream)."""
    all_indicators = []
    for line in eve_lines.strip().split("\n"):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            indicators = parse_eve_event(event)
            all_indicators.extend(indicators)
        except json.JSONDecodeError:
            continue
    return all_indicators


def extract_alert_metadata(event: dict[str, Any]) -> dict[str, Any]:
    """Extract alert metadata for storage."""
    alert = event.get("alert", {})
    return {
        "alert_id": f"suricata-{alert.get('gid', 0)}-{alert.get('signature_id', 0)}-{event.get('timestamp', '')}",
        "source": "suricata",
        "severity": {1: "high", 2: "medium", 3: "low"}.get(
            alert.get("severity", 3), "low"
        ),
        "category": alert.get("category", "unknown"),
        "payload": event,
    }


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_domain(value: str) -> bool:
    return "." in value and not _is_ip(value) and not value.startswith("http")

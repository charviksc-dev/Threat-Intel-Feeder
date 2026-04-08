"""Zeek Network Security Monitor Integration

Parses Zeek log files to extract IOCs:
- conn.log: IP connections, flow data
- dns.log: DNS queries and responses
- http.log: HTTP requests, hosts, URLs
- ssl.log: TLS certificates, SNI
- files.log: File analysis, hashes
- x509.log: Certificate details
- notice.log: Zeek notices/anomalies
- smtp.log: Email metadata

Supports both Zeek TSV format and JSON log format.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


# Zeek JSON field mappings for IOC extraction
ZEEK_IOC_PARSERS = {
    "conn": "_parse_conn_log",
    "dns": "_parse_dns_log",
    "http": "_parse_http_log",
    "ssl": "_parse_ssl_log",
    "files": "_parse_files_log",
    "notice": "_parse_notice_log",
    "x509": "_parse_x509_log",
}


def parse_zeek_json_event(
    event: dict[str, Any], log_type: str = "conn"
) -> list[dict[str, Any]]:
    """Parse a Zeek JSON log event.

    Zeek JSON format (from log-streaming or json-logs):
    {
        "ts": 1704067200.0,
        "uid": "Cx...",
        "id.orig_h": "1.2.3.4",
        "id.orig_p": 12345,
        "id.resp_h": "5.6.7.8",
        "id.resp_p": 80,
        "proto": "tcp",
        "service": "http"
    }
    """
    parser_name = ZEEK_IOC_PARSERS.get(log_type)
    if not parser_name:
        return []

    parser = globals().get(parser_name)
    if not parser:
        return []

    try:
        return parser(event)
    except Exception as e:
        logger.debug("Failed to parse Zeek %s event: %s", log_type, e)
        return []


def _ts_to_iso(ts: Any) -> str | None:
    """Convert Zeek timestamp to ISO format."""
    if ts is None:
        return None
    try:
        from datetime import datetime

        return datetime.utcfromtimestamp(float(ts)).isoformat()
    except (ValueError, OSError):
        return str(ts)


def _parse_conn_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek conn.log for connection-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    src_ip = event.get("id.orig_h") or event.get("id_orig_h")
    dst_ip = event.get("id.resp_h") or event.get("id_resp_h")
    dst_port = event.get("id.resp_p") or event.get("id_resp_p")
    proto = event.get("proto", "")
    conn_state = event.get("conn_state", "")
    history = event.get("history", "")

    # Flag suspicious connections
    threat_types = []
    tags = []

    # Detect port scans (S0 state = SYN sent, no reply)
    if conn_state == "S0":
        threat_types.append("scan")
        tags.append("port-scan")

    # Detect potential C2 (long duration connections)
    duration = event.get("duration", 0)
    if duration and float(duration) > 3600:
        threat_types.append("long-duration")
        tags.append("suspicious-connection")

    # RST responses might indicate blocked connections
    if "R" in history:
        tags.append("rst-connection")

    # Capture source IPs with suspicious activity
    if src_ip and (threat_types or dst_port in [4444, 5555, 6666, 31337]):
        indicators.append(
            {
                "indicator": src_ip,
                "type": "ipv4",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": threat_types or ["connection"],
                "tags": tags + [f"proto:{proto}"],
                "metadata": {
                    "zeek_log": "conn",
                    "uid": event.get("uid"),
                    "dest_ip": dst_ip,
                    "dest_port": dst_port,
                    "proto": proto,
                    "conn_state": conn_state,
                },
            }
        )

    return indicators


def _parse_dns_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek dns.log for DNS-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    query = event.get("query")
    qtype = event.get("qtype_name") or event.get("qtype")
    src_ip = event.get("id.orig_h") or event.get("id_orig_h")
    answers = event.get("answers", [])

    if query and query != "-":
        indicators.append(
            {
                "indicator": query,
                "type": "domain",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["dns-query"],
                "tags": [f"qtype:{qtype}", "zeek:dns"],
                "metadata": {
                    "zeek_log": "dns",
                    "uid": event.get("uid"),
                    "src_ip": src_ip,
                    "rcode": event.get("rcode"),
                    "answers": answers,
                },
            }
        )

    # Capture resolved IPs for later correlation
    for answer in answers:
        if isinstance(answer, str) and _is_ip(answer):
            indicators.append(
                {
                    "indicator": answer,
                    "type": "ipv4",
                    "source": "zeek",
                    "first_seen": ts,
                    "threat_types": ["dns-resolved"],
                    "tags": ["zeek:dns-resolved", f"domain:{query}"],
                    "metadata": {
                        "zeek_log": "dns",
                        "resolved_from": query,
                        "qtype": qtype,
                    },
                }
            )

    return indicators


def _parse_http_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek http.log for HTTP-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    host = event.get("host")
    uri = event.get("uri")
    src_ip = event.get("id.orig_h") or event.get("id_orig_h")
    user_agent = event.get("user_agent")
    method = event.get("method")

    if host and host != "-":
        indicators.append(
            {
                "indicator": host,
                "type": "domain",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["http-host"],
                "tags": ["zeek:http"],
                "metadata": {
                    "zeek_log": "http",
                    "uid": event.get("uid"),
                    "uri": uri,
                    "method": method,
                    "user_agent": user_agent,
                    "src_ip": src_ip,
                    "status_code": event.get("status_code"),
                },
            }
        )

    if uri and uri != "/" and host:
        full_url = f"http://{host}{uri}"
        indicators.append(
            {
                "indicator": full_url,
                "type": "url",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["http-url"],
                "tags": ["zeek:http"],
                "metadata": {
                    "zeek_log": "http",
                    "uid": event.get("uid"),
                    "method": method,
                    "src_ip": src_ip,
                },
            }
        )

    return indicators


def _parse_ssl_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek ssl.log for TLS-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    sni = event.get("server_name")
    src_ip = event.get("id.orig_h") or event.get("id_orig_h")
    event.get("cert_chain_fuids", [])

    if sni and sni != "-":
        indicators.append(
            {
                "indicator": sni,
                "type": "domain",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["tls-sni"],
                "tags": ["zeek:ssl"],
                "metadata": {
                    "zeek_log": "ssl",
                    "uid": event.get("uid"),
                    "src_ip": src_ip,
                    "version": event.get("version"),
                    "cipher": event.get("cipher"),
                    "ja3": event.get("ja3"),
                    "ja3s": event.get("ja3s"),
                },
            }
        )

    ja3 = event.get("ja3")
    if ja3 and ja3 != "-":
        indicators.append(
            {
                "indicator": ja3,
                "type": "hash",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["ja3-fingerprint"],
                "tags": ["zeek:ssl", "ja3"],
                "metadata": {"sni": sni, "src_ip": src_ip},
            }
        )

    return indicators


def _parse_files_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek files.log for file-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    md5 = event.get("md5")
    sha1 = event.get("sha1")
    sha256 = event.get("sha256")
    filename = event.get("filename")
    mime_type = event.get("mime_type")

    for hash_val, hash_type in [(md5, "md5"), (sha1, "sha1"), (sha256, "sha256")]:
        if hash_val and hash_val != "-":
            indicators.append(
                {
                    "indicator": hash_val,
                    "type": "hash",
                    "source": "zeek",
                    "first_seen": ts,
                    "threat_types": ["file-hash"],
                    "tags": [f"zeek:files:{hash_type}", f"mime:{mime_type}"],
                    "metadata": {
                        "zeek_log": "files",
                        "fuid": event.get("fuid"),
                        "filename": filename,
                        "mime_type": mime_type,
                        "md5": md5,
                        "sha256": sha256,
                    },
                }
            )

    return indicators


def _parse_notice_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek notice.log for Zeek-detected anomalies."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    src_ip = event.get("src") or event.get("id.orig_h") or event.get("id_orig_h")
    notice_type = event.get("note", "")
    msg = event.get("msg", "")
    action = event.get("action", "")

    threat_types = ["zeek-notice"]
    if "Scan" in notice_type:
        threat_types.append("scan")
    if "Brute" in notice_type:
        threat_types.append("bruteforce")
    if "Suspicious" in notice_type:
        threat_types.append("suspicious")

    if src_ip and src_ip != "-":
        indicators.append(
            {
                "indicator": src_ip,
                "type": "ipv4",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": threat_types,
                "tags": [f"notice:{notice_type}", f"action:{action}"],
                "metadata": {
                    "zeek_log": "notice",
                    "notice_type": notice_type,
                    "msg": msg,
                    "action": action,
                    "dst": event.get("dst")
                    or event.get("id.resp_h")
                    or event.get("id_resp_h"),
                },
            }
        )

    return indicators


def _parse_x509_log(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Zeek x509.log for certificate-based IOCs."""
    indicators = []
    ts = _ts_to_iso(event.get("ts"))
    cert_hash = event.get("certificate.sha256") or event.get("certificate", {}).get(
        "sha256"
    )
    subject = event.get("certificate.subject") or event.get("certificate", {}).get(
        "subject"
    )
    issuer = event.get("certificate.issuer") or event.get("certificate", {}).get(
        "issuer"
    )

    if cert_hash and cert_hash != "-":
        indicators.append(
            {
                "indicator": cert_hash,
                "type": "hash",
                "source": "zeek",
                "first_seen": ts,
                "threat_types": ["certificate-hash"],
                "tags": ["zeek:x509"],
                "metadata": {
                    "zeek_log": "x509",
                    "subject": subject,
                    "issuer": issuer,
                },
            }
        )

    return indicators


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

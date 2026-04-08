from datetime import datetime
from typing import Any

TYPE_MAP = {
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "fqdn": "domain",
    "url": "url",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "cve": "cve",
    "email": "email",
}

DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d",
    "%d-%m-%Y",
    "%m/%d/%Y",
]


def normalize_date(value: Any) -> str | None:
    """Normalize various date formats to ISO 8601."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        # Unix timestamp
        try:
            return datetime.utcfromtimestamp(value).isoformat()
        except (ValueError, OSError):
            return None
    if isinstance(value, str):
        value = value.strip()
        # Already ISO format
        if "T" in value and (value.endswith("Z") or "+" in value):
            return value
        for fmt in DATE_FORMATS:
            try:
                dt = datetime.strptime(value, fmt)
                return dt.isoformat()
            except ValueError:
                continue
    return None


def normalize_indicator(raw: dict[str, Any]) -> dict[str, Any]:
    indicator = raw.get("indicator")
    raw_type = raw.get("type", "unknown")
    normalized_type = TYPE_MAP.get(raw_type.lower(), raw_type.lower())

    return {
        "indicator": indicator,
        "type": normalized_type,
        "source": raw.get("source", "unknown"),
        "first_seen": normalize_date(raw.get("first_seen")),
        "last_seen": normalize_date(raw.get("last_seen")),
        "confidence_score": raw.get("confidence_score", 0.0),
        "tags": raw.get("tags", []),
        "threat_types": raw.get("threat_types", []),
        "metadata": raw.get("metadata", {}),
        "geo": raw.get("geo"),
        "relationships": raw.get("relationships", []),
        "context": raw.get("context", ""),
    }

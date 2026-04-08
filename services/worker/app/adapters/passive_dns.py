import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

IPINFO_URL = "https://ipinfo.io/{ip}/json"
GOOGLE_DNS_URL = "https://dns.google/resolve"


def enrich_asn(ip: str) -> dict[str, Any]:
    """Enrich an IP address with ASN and geolocation data from ipinfo.io.

    Returns dict with: asn, asn_name, country, city, lat, lng.
    Returns empty dict on error.
    """
    headers = {"Accept": "application/json"}
    if settings.IPINFO_API_KEY:
        headers["Authorization"] = f"Bearer {settings.IPINFO_API_KEY}"

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            url = IPINFO_URL.format(ip=ip)
            response = client.get(url)
            response.raise_for_status()
            data = response.json()

            # ipinfo returns loc as "lat,lng" string
            loc = data.get("loc", "")
            lat, lng = None, None
            if loc:
                parts = loc.split(",")
                if len(parts) == 2:
                    try:
                        lat = float(parts[0])
                        lng = float(parts[1])
                    except ValueError:
                        pass

            # ASN is returned as "AS####" in the 'org' field, parse it
            org = data.get("org", "")
            asn = ""
            asn_name = ""
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    asn = parts[0]
                    asn_name = parts[1] if len(parts) > 1 else ""
                else:
                    asn_name = org

            return {
                "asn": asn,
                "asn_name": asn_name,
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "lat": lat,
                "lng": lng,
            }
    except Exception as e:
        logger.warning("Failed to enrich ASN for IP %s: %s", ip, e)
        return {}


def enrich_passive_dns(domain: str) -> list[dict[str, Any]]:
    """Enrich a domain with passive DNS data using Google DNS over HTTPS.

    Returns list of DNS record dicts with: name, type, ttl, data.
    Returns empty list on error.
    """
    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                GOOGLE_DNS_URL,
                params={"name": domain, "type": "A"},
            )
            response.raise_for_status()
            data = response.json()

            records = []
            for answer in data.get("Answer", []):
                records.append(
                    {
                        "name": answer.get("name", ""),
                        "type": answer.get("type", 0),
                        "ttl": answer.get("TTL", 0),
                        "data": answer.get("data", ""),
                    }
                )
            return records
    except Exception as e:
        logger.warning("Failed to enrich passive DNS for domain %s: %s", domain, e)
        return []


def enrich_whois_data(domain: str) -> dict[str, Any]:
    """Enrich a domain with WHOIS data.

    Uses python-whois if available, otherwise falls back to a web lookup.
    Returns dict with: registrar, created, expires, nameservers.
    Returns empty dict on error.
    """
    try:
        import whois as whois_module

        w = whois_module.whois(domain)

        registrar = w.registrar or ""
        created = w.creation_date
        expires = w.expiration_date
        nameservers = w.name_servers or []

        # Normalize dates to strings
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(expires, list):
            expires = expires[0] if expires else None

        return {
            "registrar": registrar,
            "created": str(created) if created else "",
            "expires": str(expires) if expires else "",
            "nameservers": [str(ns) for ns in nameservers] if nameservers else [],
        }
    except ImportError:
        logger.debug("python-whois not installed, returning empty WHOIS data")
        return {}
    except Exception as e:
        logger.warning("Failed to enrich WHOIS data for domain %s: %s", domain, e)
        return {}

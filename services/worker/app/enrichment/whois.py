import logging
from typing import Any

import whois

logger = logging.getLogger(__name__)


def get_whois_data(domain: str) -> dict[str, Any]:
    try:
        record = whois.whois(domain)
        return {
            "domain_name": record.domain_name,
            "registrar": record.registrar,
            "creation_date": record.creation_date,
            "expiration_date": record.expiration_date,
            "updated_date": record.updated_date,
            "name_servers": record.name_servers,
        }
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {}

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def get_geoip_data(ip_address: str) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as"
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "success":
                return {}
            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
            }
    except Exception:
        return {}

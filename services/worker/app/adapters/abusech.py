import csv
import logging
from io import StringIO
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def fetch_abusech_indicators() -> list[dict[str, Any]]:
    # Override configured URL with active SSLBL source
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

    with httpx.Client(timeout=30) as client:
        response = client.get(url)
        response.raise_for_status()

    text = response.text
    reader = csv.reader(StringIO(text))
    indicators: list[dict[str, Any]] = []
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        try:
            # Format: First seen,DstIP,DstPort
            ip = row[1]
            indicators.append(
                {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": "abusech",
                    "first_seen": row[0],
                    "metadata": {"origin": url, "port": row[2] if len(row) > 2 else None},
                }
            )
        except Exception:
            continue
    return indicators

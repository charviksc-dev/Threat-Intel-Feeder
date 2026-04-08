from datetime import datetime
from typing import Any


def compute_confidence_score(indicator: str, metadata: dict[str, Any]) -> float:
    score = 10.0
    feed_count = metadata.get("feed_count", 1)
    vt_score = metadata.get("vt_score") or 0
    tags = metadata.get("tags", [])
    first_seen = metadata.get("first_seen")
   
    score += min(feed_count, 5) * 10
    score += min(max(vt_score, 0), 100) * 0.4
    score += len(tags) * 2

    if first_seen:
        try:
            age = datetime.utcnow() - datetime.fromisoformat(first_seen)
            if age.days < 30:
                score += 10
            elif age.days < 90:
                score += 4
        except ValueError:
            pass

    return round(max(0.0, min(100.0, score)), 2)

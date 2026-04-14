"""
Synthetic Intelligence Engine for Threat Intelligence Analysis.

This module provides ML-based threat analysis, pattern recognition,
and behavioral anomaly detection for threat intelligence data.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re
from collections import Counter

logger = logging.getLogger(__name__)


@dataclass
class ThreatPattern:
    """Represents a detected threat pattern."""
    pattern_type: str
    confidence: float
    indicators: List[str]
    description: str
    mitre_techniques: List[str]
    severity: str


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: str
    severity: str
    description: str
    affected_indicators: List[str]
    score: float


class SyntheticIntelligenceEngine:
    """
    Synthetic Intelligence Engine for threat intelligence analysis.
    
    Features:
    - Pattern recognition for attack chains
    - Behavioral anomaly detection
    - ML-based threat scoring
    - Predictive analytics
    """

    def __init__(self):
        self.patterns = self._load_threat_patterns()
        self.attack_chains = self._load_attack_chains()
        self.risk_weights = self._load_risk_weights()

    def _load_threat_patterns(self) -> Dict[str, Dict]:
        """Load known threat patterns for detection."""
        return {
            "c2_infrastructure": {
                "indicators": ["ip", "domain"],
                "patterns": [
                    r".*\.ddns\.net$",
                    r".*\.no-ip\.",
                    r".*\.dyndns\.",
                    r".*\.duckdns\.",
                ],
                "severity": "high",
                "mitre": ["T1071", "T1102"],
            },
            "phishing_kit": {
                "indicators": ["domain", "url"],
                "patterns": [
                    r".*(login|signin|account|verify|secure|bank).*\.(com|net|org)",
                    r".*paypal.*\.com$",
                    r".*apple.*\.com$",
                ],
                "severity": "critical",
                "mitre": ["T1566", "T1593"],
            },
            "crypto_mining": {
                "indicators": ["domain", "url"],
                "patterns": [
                    r".*(mine|pool|crypto|coin).*",
                    r".*stratum.*tcp.*",
                ],
                "severity": "medium",
                "mitre": ["T1496"],
            },
            "malware_family": {
                "indicators": ["domain", "hash"],
                "patterns": [
                    r".*emotet.*",
                    r".*trickbot.*",
                    r".*ryuk.*",
                    r".*conti.*",
                ],
                "severity": "critical",
                "mitre": ["T1059", "T1204"],
            },
        }

    def _load_attack_chains(self) -> Dict[str, List[str]]:
        """Load MITRE ATT&CK attack chain mappings."""
        return {
            "initial_access": ["T1566", "T1190", "T1078"],
            "execution": ["T1059", "T1204", "T1106"],
            "persistence": ["T1543", "T1053", "T1547"],
            "privilege_escalation": ["T1068", "T1484", "T1134"],
            "defense_evasion": ["T1562", "T1564", "T1222"],
            "credential_access": ["T1056", "T1110", "T1552"],
            "discovery": ["T1018", "T1087", "T1135"],
            "lateral_movement": ["T1021", "T1570", "T1028"],
            "collection": ["T1113", "T1005", "T1119"],
            "exfiltration": ["T1041", "T1567", "T1530"],
            "command_and_control": ["T1071", "T1102", "T1571"],
            "impact": ["T1486", "T1489", "T1529"],
        }

    def _load_risk_weights(self) -> Dict[str, float]:
        """Load risk weighting factors for scoring."""
        return {
            "source_reliability": 0.25,
            "recency": 0.20,
            "correlation_count": 0.20,
            "threat_type_severity": 0.15,
            "geographic_risk": 0.10,
            "behavioral_anomaly": 0.10,
        }

    def analyze_patterns(
        self, indicators: List[Dict[str, Any]]
    ) -> List[ThreatPattern]:
        """
        Detect threat patterns in indicators.
        
        Args:
            indicators: List of indicator dictionaries
            
        Returns:
            List of detected threat patterns
        """
        detected_patterns = []
        
        for pattern_name, pattern_config in self.patterns.items():
            matched_indicators = []
            
            for indicator in indicators:
                indicator_value = indicator.get("indicator", "")
                indicator_type = indicator.get("type", "")
                
                if indicator_type in pattern_config["indicators"]:
                    for pattern_regex in pattern_config["patterns"]:
                        if re.search(pattern_regex, indicator_value, re.IGNORECASE):
                            matched_indicators.append(indicator_value)
                            break
            
            if matched_indicators:
                confidence = min(0.95, len(matched_indicators) * 0.15 + 0.5)
                detected_patterns.append(
                    ThreatPattern(
                        pattern_type=pattern_name,
                        confidence=confidence,
                        indicators=matched_indicators[:10],  # Limit to top 10
                        description=self._get_pattern_description(pattern_name),
                        mitre_techniques=pattern_config["mitre"],
                        severity=pattern_config["severity"],
                    )
                )
        
        return detected_patterns

    def detect_anomalies(
        self, indicators: List[Dict[str, Any]]
    ) -> List[Anomaly]:
        """
        Detect behavioral anomalies in indicators.
        
        Args:
            indicators: List of indicator dictionaries
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        if not indicators:
            return anomalies
        
        # Anomaly 1: High concentration from single ASN
        asns = [ind.get("asn", "") for ind in indicators if ind.get("asn")]
        asn_counts = Counter(asns)
        if asn_counts:
            top_asn, count = asn_counts.most_common(1)[0]
            if count > len(indicators) * 0.3:  # More than 30% from single ASN
                anomalies.append(
                    Anomaly(
                        anomaly_type="asn_concentration",
                        severity="medium",
                        description=f"High concentration ({count}/{len(indicators)}) from ASN {top_asn}",
                        affected_indicators=[
                            ind["indicator"] for ind in indicators
                            if ind.get("asn") == top_asn
                        ][:10],
                        score=0.7,
                    )
                )
        
        # Anomaly 2: Unusual geographic clustering
        countries = [
            ind.get("geo", {}).get("country", "")
            for ind in indicators
            if ind.get("geo", {}).get("country")
        ]
        country_counts = Counter(countries)
        if country_counts:
            top_country, count = country_counts.most_common(1)[0]
            if count > len(indicators) * 0.5:  # More than 50% from single country
                anomalies.append(
                    Anomaly(
                        anomaly_type="geographic_clustering",
                        severity="low",
                        description=f"Unusual geographic clustering ({count}/{len(indicators)}) in {top_country}",
                        affected_indicators=[
                            ind["indicator"] for ind in indicators
                            if ind.get("geo", {}).get("country") == top_country
                        ][:10],
                        score=0.5,
                    )
                )
        
        # Anomaly 3: Recent surge in similar indicators
        timestamps = [
            ind.get("first_seen", "")
            for ind in indicators
            if ind.get("first_seen")
        ]
        if timestamps:
            recent_count = sum(
                1
                for ts in timestamps
                if datetime.fromisoformat(ts) > datetime.now() - timedelta(hours=24)
            )
            if recent_count > len(indicators) * 0.7:  # More than 70% in last 24h
                anomalies.append(
                    Anomaly(
                        anomaly_type="temporal_surge",
                        severity="high",
                        description=f"Recent surge: {recent_count}/{len(indicators)} indicators in last 24h",
                        affected_indicators=[
                            ind["indicator"]
                            for ind in indicators
                            if ind.get("first_seen")
                            and datetime.fromisoformat(ind["first_seen"])
                            > datetime.now() - timedelta(hours=24)
                        ][:10],
                        score=0.85,
                    )
                )
        
        # Anomaly 4: Unusual TLD distribution
        tlds = []
        for ind in indicators:
            indicator = ind.get("indicator", "")
            if "." in indicator and ind.get("type") in ["domain", "url"]:
                tld = indicator.split(".")[-1]
                tlds.append(tld)
        
        if tlds:
            tld_counts = Counter(tlds)
            top_tld, count = tld_counts.most_common(1)[0]
            if count > len(tlds) * 0.4 and top_tld not in ["com", "net", "org"]:
                anomalies.append(
                    Anomaly(
                        anomaly_type="tld_anomaly",
                        severity="medium",
                        description=f"Unusual TLD distribution: {count}/{len(tlds)} from .{top_tld}",
                        affected_indicators=[
                            ind["indicator"]
                            for ind in indicators
                            if ind.get("indicator", "").endswith(f".{top_tld}")
                        ][:10],
                        score=0.6,
                    )
                )
        
        return anomalies

    def calculate_threat_score(
        self, indicator: Dict[str, Any]
    ) -> float:
        """
        Calculate ML-based threat score for an indicator.
        
        Args:
            indicator: Indicator dictionary
            
        Returns:
            Threat score (0-100)
        """
        score = 0.0
        weights = self.risk_weights
        
        # Source reliability
        source = indicator.get("source", "")
        if source in ["virustotal", "otx", "misp"]:
            score += weights["source_reliability"] * 100
        elif source in ["urlhaus", "threatfox"]:
            score += weights["source_reliability"] * 80
        else:
            score += weights["source_reliability"] * 60
        
        # Recency
        first_seen = indicator.get("first_seen", "")
        if first_seen:
            try:
                seen_date = datetime.fromisoformat(first_seen)
                days_old = (datetime.now() - seen_date).days
                recency_score = max(0, 100 - days_old * 2)  # Decay by 2 points per day
                score += weights["recency"] * recency_score
            except:
                score += weights["recency"] * 50
        else:
            score += weights["recency"] * 30
        
        # Threat type severity
        threat_types = indicator.get("threat_types", [])
        if threat_types:
            high_severity = ["malware", "c2", "phishing", "ransomware"]
            if any(t in high_severity for t in threat_types):
                score += weights["threat_type_severity"] * 100
            else:
                score += weights["threat_type_severity"] * 70
        else:
            score += weights["threat_type_severity"] * 50
        
        # Geographic risk
        geo = indicator.get("geo", {})
        country = geo.get("country", "")
        high_risk_countries = ["CN", "RU", "KP", "IR", "SY"]
        if country in high_risk_countries:
            score += weights["geographic_risk"] * 80
        elif country:
            score += weights["geographic_risk"] * 40
        else:
            score += weights["geographic_risk"] * 20
        
        # Confidence score from feed
        confidence = indicator.get("confidence_score", 0.5)
        score += weights["correlation_count"] * (confidence * 100)
        
        # Behavioral anomaly (placeholder - would need historical data)
        score += weights["behavioral_anomaly"] * 50
        
        return min(100, score)

    def reconstruct_attack_chain(
        self, indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Reconstruct potential attack chain from indicators.
        
        Args:
            indicators: List of indicator dictionaries
            
        Returns:
            Attack chain analysis
        """
        threat_types = set()
        for ind in indicators:
            threat_types.update(ind.get("threat_types", []))
        
        # Map threat types to ATT&CK tactics
        detected_stages = []
        if "phishing" in threat_types:
            detected_stages.append("initial_access")
        if "malware" in threat_types:
            detected_stages.extend(["execution", "persistence"])
        if "c2" in threat_types:
            detected_stages.append("command_and_control")
        if "exfiltration" in threat_types:
            detected_stages.append("exfiltration")
        if "ransomware" in threat_types:
            detected_stages.extend(["impact", "defense_evasion"])
        
        # Get MITRE techniques for detected stages
        techniques = []
        for stage in detected_stages:
            techniques.extend(self.attack_chains.get(stage, []))
        
        # Calculate completion percentage
        total_stages = len(self.attack_chains)
        completion = len(detected_stages) / total_stages * 100
        
        return {
            "detected_stages": detected_stages,
            "mitre_techniques": list(set(techniques)),
            "completion_percentage": round(completion, 1),
            "likely_attackers": self._identify_likely_attackers(threat_types),
            "next_predicted_stages": self._predict_next_stages(detected_stages),
        }

    def predict_threat_trend(
        self, historical_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Predict future threat trends based on historical data.
        
        Args:
            historical_data: Historical indicator data
            
        Returns:
            Threat trend predictions
        """
        if not historical_data:
            return {
                "prediction": "insufficient_data",
                "confidence": 0,
                "trend": "unknown",
            }
        
        # Count indicators by date
        date_counts = Counter()
        for ind in historical_data:
            first_seen = ind.get("first_seen", "")
            if first_seen:
                try:
                    date = datetime.fromisoformat(first_seen).date()
                    date_counts[date] += 1
                except:
                    pass
        
        if not date_counts:
            return {
                "prediction": "insufficient_data",
                "confidence": 0,
                "trend": "unknown",
            }
        
        # Simple trend analysis
        sorted_dates = sorted(date_counts.keys())
        recent_counts = [date_counts[d] for d in sorted_dates[-7:]]
        older_counts = [date_counts[d] for d in sorted_dates[-14:-7]] if len(sorted_dates) >= 14 else []
        
        if not older_counts:
            return {
                "prediction": "insufficient_history",
                "confidence": 0.3,
                "trend": "unknown",
            }
        
        recent_avg = sum(recent_counts) / len(recent_counts)
        older_avg = sum(older_counts) / len(older_counts)
        
        if recent_avg > older_avg * 1.5:
            trend = "increasing"
            prediction = "expect_escalation"
            confidence = 0.75
        elif recent_avg < older_avg * 0.5:
            trend = "decreasing"
            prediction = "expect_decline"
            confidence = 0.7
        else:
            trend = "stable"
            prediction = "expect_continuation"
            confidence = 0.6
        
        # Predict next 7 days
        predicted_daily = round(recent_avg)
        predicted_weekly = predicted_daily * 7
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "trend": trend,
            "current_daily_avg": round(recent_avg),
            "predicted_daily_avg": predicted_daily,
            "predicted_weekly_total": predicted_weekly,
            "forecast_period": "7 days",
        }

    def _get_pattern_description(self, pattern_name: str) -> str:
        """Get human-readable description for a pattern."""
        descriptions = {
            "c2_infrastructure": "Command and Control infrastructure detected, typical of malware communication channels",
            "phishing_kit": "Phishing kit infrastructure detected, likely credential harvesting operation",
            "crypto_mining": "Cryptocurrency mining infrastructure detected, resource abuse activity",
            "malware_family": "Known malware family indicators detected, active malicious campaign",
        }
        return descriptions.get(pattern_name, "Unknown threat pattern")

    def _identify_likely_attackers(self, threat_types: set) -> List[str]:
        """Identify likely threat actors based on threat types."""
        actor_mapping = {
            "phishing": ["APT41", "FIN7", "TA505"],
            "malware": ["APT29", "Lazarus Group", "MuddyWater"],
            "c2": ["APT28", "OilRig", "Kimsuky"],
            "ransomware": ["Conti", "LockBit", "REvil"],
        }
        
        actors = set()
        for t_type in threat_types:
            actors.update(actor_mapping.get(t_type, []))
        
        return list(actors)[:5]

    def _predict_next_stages(self, current_stages: List[str]) -> List[str]:
        """Predict next likely attack stages."""
        stage_order = [
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "command_and_control",
            "impact",
        ]
        
        if not current_stages:
            return ["initial_access", "execution"]
        
        last_stage_idx = max(
            [stage_order.index(s) for s in current_stages if s in stage_order]
        )
        
        next_stages = []
        for i in range(last_stage_idx + 1, min(last_stage_idx + 3, len(stage_order))):
            next_stages.append(stage_order[i])
        
        return next_stages


# Global instance
ai_engine = SyntheticIntelligenceEngine()

# Synthetic Intelligence Layer Documentation

## Overview

The Neev Threat Intelligence Platform now includes a comprehensive Synthetic Intelligence Engine (v3.0) that provides ML-based threat analysis, pattern recognition, behavioral anomaly detection, and predictive analytics.

## Features

### 1. Pattern Recognition

The AI engine detects known threat patterns in indicators:

- **C2 Infrastructure**: Detects command and control domains/ips (DDNS, no-ip, dyndns, duckdns)
- **Phishing Kits**: Identifies phishing infrastructure (login/signin/verify domains, brand impersonation)
- **Crypto Mining**: Detects cryptocurrency mining infrastructure
- **Malware Families**: Identifies indicators associated with known malware (Emotet, Trickbot, Ryuk, Conti)

### 2. Behavioral Anomaly Detection

Detects unusual patterns in indicator data:

- **ASN Concentration**: Identifies when >30% of indicators come from a single ASN
- **Geographic Clustering**: Detects unusual concentration in specific countries
- **Temporal Surges**: Identifies sudden increases in indicator volume (>70% in 24h)
- **TLD Anomalies**: Detects unusual top-level domain distributions

### 3. MITRE ATT&CK Attack Chain Reconstruction

Reconstructs attack chains from indicators:

- Maps threat types to ATT&CK tactics (12 stages)
- Identifies likely MITRE techniques
- Predicts next attack stages
- Identifies likely threat actors (APT41, FIN7, APT29, Lazarus, Conti, etc.)

### 4. ML-Based Threat Scoring

Calculates composite threat scores based on:

- Source reliability (25%): VirusTotal, OTX, MISP (100) > URLhaus, ThreatFox (80) > others (60)
- Recency (20%): Decays by 2 points per day
- Threat type severity (15%): Malware/C2/Phishing/Ransomware (100) > others (70)
- Geographic risk (10%): High-risk countries (CN, RU, KP, IR, SY) > others
- Correlation count (20%): Based on confidence score
- Behavioral anomaly (10%): Historical pattern analysis

### 5. Predictive Analytics

Forecast threat trends based on historical data:

- Analyzes 30-day historical indicator trends
- Predicts next 7-day threat volume
- Identifies increasing/decreasing/stable trends
- Provides confidence scores for predictions

## API Endpoints

### 1. Comprehensive AI Analysis

**Endpoint:** `GET /api/v1/ai/analyze`

**Parameters:**
- `indicators` (optional): Comma-separated list of specific indicators to analyze
- If not provided, analyzes last 24 hours of indicators

**Response:**
```json
{
  "id": "analysis-1",
  "timestamp": "2026-04-14T09:30:00",
  "total_indicators_analyzed": 500,
  "model": "Neev TIP Synthetic Intelligence Engine v3.0",
  "overall_threat_score": 72.5,
  "detected_patterns": [...],
  "detected_anomalies": [...],
  "attack_chain_analysis": {...},
  "recommendations": [...],
  "confidence_uncertainty": "±3"
}
```

### 2. Pattern Detection

**Endpoint:** `GET /api/v1/ai/patterns`

**Parameters:**
- `q` (optional): Search query to filter indicators
- Default: Analyzes last 7 days of indicators

**Response:**
```json
{
  "indicators_analyzed": 500,
  "patterns_detected": 3,
  "patterns": [
    {
      "type": "c2_infrastructure",
      "confidence": 0.85,
      "severity": "high",
      "description": "Command and Control infrastructure detected...",
      "mitre_techniques": ["T1071", "T1102"],
      "indicator_count": 25,
      "indicators": ["malicious.ddns.net", ...]
    }
  ]
}
```

### 3. Anomaly Detection

**Endpoint:** `GET /api/v1/ai/anomalies`

**Parameters:**
- `hours` (default: 24): Time window in hours to analyze

**Response:**
```json
{
  "time_window_hours": 24,
  "indicators_analyzed": 1000,
  "anomalies_detected": 2,
  "anomalies": [
    {
      "type": "temporal_surge",
      "severity": "high",
      "description": "Recent surge: 800/1000 indicators in last 24h",
      "score": 0.85,
      "affected_count": 800,
      "indicators": [...]
    }
  ]
}
```

### 4. Attack Chain Reconstruction

**Endpoint:** `GET /api/v1/ai/attack-chain`

**Parameters:**
- `indicator`: Indicator value to analyze

**Response:**
```json
{
  "indicator": "192.168.1.1",
  "threat_score": 85.2,
  "attack_chain": {
    "detected_stages": ["initial_access", "execution", "command_and_control"],
    "mitre_techniques": ["T1566", "T1059", "T1071"],
    "completion_percentage": 25.0,
    "likely_attackers": ["APT41", "FIN7"],
    "next_predicted_stages": ["persistence", "privilege_escalation"]
  },
  "related_indicators_count": 50,
  "sample_related_indicators": [...]
}
```

### 5. Threat Trend Prediction

**Endpoint:** `GET /api/v1/ai/predict`

**Parameters:**
- `days` (default: 30): Historical days to analyze

**Response:**
```json
{
  "prediction": "expect_escalation",
  "confidence": 0.75,
  "trend": "increasing",
  "current_daily_avg": 150,
  "predicted_daily_avg": 150,
  "predicted_weekly_total": 1050,
  "forecast_period": "7 days"
}
```

### 6. Threat Scoring

**Endpoint:** `GET /api/v1/ai/score`

**Parameters:**
- `indicator`: Indicator value to score

**Response:**
```json
{
  "indicator": "192.168.1.1",
  "threat_score": 72.5,
  "score_breakdown": {
    "source_reliability": 25.0,
    "recency": 10.0,
    "threat_type_severity": 15.0,
    "geographic_risk": 8.0,
    "correlation_count": 14.0,
    "behavioral_anomaly": 5.0
  }
}
```

### 7. Analysis History

**Endpoint:** `GET /api/v1/ai/history`

**Response:** Returns last 10 AI analyses

### 8. Analyst Feedback

**Endpoint:** `POST /api/v1/ai/feedback`

**Parameters:**
- `analysis_id`: ID of the analysis
- `is_positive`: Boolean feedback
- `comment` (optional): Additional feedback

**Response:** Confirmation of feedback recording

## Usage Examples

### Analyze Recent Threats
```bash
curl http://localhost:8000/api/v1/ai/analyze
```

### Analyze Specific Indicators
```bash
curl "http://localhost:8000/api/v1/ai/analyze?indicators=192.168.1.1,example.com"
```

### Detect Patterns in Last 7 Days
```bash
curl http://localhost:8000/api/v1/ai/patterns
```

### Detect Anomalies in Last 48 Hours
```bash
curl "http://localhost:8000/api/v1/ai/anomalies?hours=48"
```

### Reconstruct Attack Chain
```bash
curl "http://localhost:8000/api/v1/ai/attack-chain?indicator=192.168.1.1"
```

### Predict Threat Trends
```bash
curl "http://localhost:8000/api/v1/ai/predict?days=60"
```

### Calculate Threat Score
```bash
curl "http://localhost:8000/api/v1/ai/score?indicator=example.com"
```

## Recommendations Engine

The AI engine generates actionable recommendations based on:

1. **Pattern-based**: Block C2 infrastructure, isolate malware-infected systems
2. **Anomaly-based**: Investigate temporal surges, review high-risk ASNs
3. **Attack chain-based**: Initiate incident response for advanced attacks

Recommendations include priority levels (critical, high, medium, low) and specific action items.

## MITRE ATT&CK Integration

The engine maps detected threats to MITRE ATT&CK framework:

- **Tactics**: 12 attack stages from initial access to impact
- **Techniques**: Specific techniques for each tactic
- **Threat Actors**: Likely APT groups based on TTPs

## Configuration

AI features are enabled by default. Configuration options in `.env`:

```bash
# AI Features
AI_SUMMARIZE_ENABLED=true
```

## Performance Considerations

- Pattern detection: O(n) where n is number of indicators
- Anomaly detection: O(n) with statistical analysis
- Attack chain reconstruction: O(n + m) where m is related indicators
- Prediction analysis: O(n) for historical data processing

Recommended limits:
- Analyze max 1000 indicators per request
- Use time window filters for large datasets
- Cache results for frequently analyzed indicators

## Future Enhancements

Planned improvements to the synthetic intelligence layer:

1. **Machine Learning Models**: Train custom models on historical threat data
2. **Natural Language Processing**: Generate human-readable threat reports
3. **Graph-Based Analysis**: Visualize threat actor relationships
4. **Real-Time Scoring**: Stream-based threat scoring for live feeds
5. **Feedback Learning**: Improve models based on analyst feedback
6. **Multi-Modal Analysis**: Combine network, file, and behavioral data
7. **Threat Actor Profiling**: Detailed threat actor behavior analysis
8. **Campaign Tracking**: Track and correlate related threat campaigns

## Support

For issues or questions about the AI features, refer to:
- Main documentation: `README.md`
- API documentation: Available at `/docs` endpoint
- Health check: `/api/v1/health/extended`

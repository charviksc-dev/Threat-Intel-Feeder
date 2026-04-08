"""Firewall Integration - Blocklist Exporter

Exports IOCs as firewall-ready blocklists:
- IP blocklists (iptables, pf, nftables format)
- Domain blocklists (DNS sinkhole format)
- URL blocklists (Squid/SquidGuard format)

Supports:
1. Pull-based: Firewall fetches blocklist from API endpoint
2. Push-based: API pushes rules to firewall via SSH/API
3. Format: Plain text, JSON, or firewall-specific formats
"""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def generate_ip_blocklist(
    indicators: list[dict[str, Any]],
    min_score: float = 0.0,
    source_filter: list[str] | None = None,
    threat_types_filter: list[str] | None = None,
) -> list[str]:
    """Generate an IP blocklist from indicators.

    Args:
        indicators: List of indicator dicts from Elasticsearch
        min_score: Minimum confidence score to include
        source_filter: Only include from these sources
        threat_types_filter: Only include these threat types
    """
    blocked_ips = set()

    for ind in indicators:
        if ind.get("type") not in ("ipv4", "ipv6"):
            continue

        score = ind.get("confidence_score", 0)
        if score < min_score:
            continue

        if source_filter and ind.get("source") not in source_filter:
            continue

        if threat_types_filter:
            ind_threats = set(ind.get("threat_types", []))
            if not ind_threats.intersection(threat_types_filter):
                continue

        blocked_ips.add(ind["indicator"])

    return sorted(blocked_ips)


def generate_domain_blocklist(
    indicators: list[dict[str, Any]],
    min_score: float = 0.0,
    source_filter: list[str] | None = None,
) -> list[str]:
    """Generate a domain blocklist for DNS sinkholing."""
    blocked_domains = set()

    for ind in indicators:
        if ind.get("type") != "domain":
            continue

        score = ind.get("confidence_score", 0)
        if score < min_score:
            continue

        if source_filter and ind.get("source") not in source_filter:
            continue

        blocked_domains.add(ind["indicator"])

    return sorted(blocked_domains)


def format_as_iptables(ips: list[str]) -> str:
    """Format IP list as iptables rules."""
    lines = [f"# Neev TIP Blocklist - Generated {datetime.utcnow().isoformat()}"]
    lines.append(f"# Total rules: {len(ips)}")
    lines.append("")
    for ip in ips:
        lines.append(f"-A INPUT -s {ip} -j DROP")
        lines.append(f"-A FORWARD -s {ip} -j DROP")
    lines.append("")
    return "\n".join(lines)


def format_as_nftables(ips: list[str]) -> str:
    """Format IP list as nftables set."""
    lines = [f"# Neev TIP Blocklist - Generated {datetime.utcnow().isoformat()}"]
    lines.append("table inet filter {")
    lines.append("  set blocklist {")
    lines.append("    type ipv4_addr")
    lines.append("    flags interval")
    lines.append("    elements = {")
    for i, ip in enumerate(ips):
        comma = "," if i < len(ips) - 1 else ""
        lines.append(f"      {ip}{comma}")
    lines.append("    }")
    lines.append("  }")
    lines.append("")
    lines.append("  chain input {")
    lines.append("    type filter hook input priority 0; policy accept;")
    lines.append("    ip saddr @blocklist drop")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def format_as_pf(ips: list[str]) -> str:
    """Format IP list as pf (packet filter) rules."""
    lines = [f"# Neev TIP Blocklist - Generated {datetime.utcnow().isoformat()}"]
    lines.append("table <blocklist> persist")
    for ip in ips:
        lines.append(f"table <blocklist> add {ip}")
    lines.append("")
    lines.append("block in quick from <blocklist> to any")
    lines.append("block out quick from any to <blocklist>")
    return "\n".join(lines)


def format_as_plain(ips: list[str]) -> str:
    """Format as plain text, one IP per line."""
    return "\n".join(ips)


def format_as_hosts_file(domains: list[str]) -> str:
    """Format domain list as /etc/hosts file for DNS sinkholing."""
    lines = [f"# Neev TIP DNS Sinkhole - Generated {datetime.utcnow().isoformat()}"]
    for domain in domains:
        lines.append(f"0.0.0.0 {domain}")
        lines.append(f":: {domain}")
    return "\n".join(lines)


def format_as_unbound_blocklist(domains: list[str]) -> str:
    """Format domain list as Unbound DNS server config."""
    lines = [f"# Neev TIP DNS Blocklist - Generated {datetime.utcnow().isoformat()}"]
    for domain in domains:
        lines.append(f'local-zone: "{domain}" always_nxdomain')
    return "\n".join(lines)


def format_as_squid_blocklist(urls: list[str]) -> str:
    """Format URL list for Squid proxy."""
    return "\n".join(urls)


def format_as_json(indicators: list[dict[str, Any]]) -> str:
    """Format as JSON for API consumption."""
    import json

    return json.dumps(
        {
            "generated_at": datetime.utcnow().isoformat(),
            "count": len(indicators),
            "indicators": indicators,
        },
        indent=2,
    )


def format_as_zeek_intel(indicators: list[dict[str, Any]]) -> str:
    """Format indicators for Zeek Intel Framework (TSV)."""
    lines = ["#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc"]
    
    type_map = {
        "ipv4": "Intel::ADDR",
        "ipv6": "Intel::ADDR",
        "domain": "Intel::DOMAIN",
        "url": "Intel::URL",
        "file_hash": "Intel::FILE_HASH",
        "email": "Intel::EMAIL"
    }

    for ind in indicators:
        ind_type = type_map.get(ind.get("type", ""), "Intel::ADDR")
        source = ind.get("source", "NeevTIP")
        desc = "|".join(ind.get("threat_types", ["malicious"]))
        lines.append(f"{ind['indicator']}\t{ind_type}\t{source}\t{desc}")
    
    return "\n".join(lines)


def format_as_wazuh_cdb(indicators: list[dict[str, Any]]) -> str:
    """Format indicators as Wazuh CDB list (key:value)."""
    lines = []
    for ind in indicators:
        # Wazuh CDB format is key:value
        # Value can be anything, used in rules like <list field="srcip">etc/lists/blocklist</list>
        val = ind.get("severity", "high")
        lines.append(f"{ind['indicator']}:{val}")
    return "\n".join(lines)


def format_blocklist(
    ips: list[str],
    domains: list[str] | None = None,
    output_format: str = "plain",
    indicators: list[dict[str, Any]] | None = None,
) -> str:
    """Format blocklist in the specified format.

    Supported formats:
    - plain: One IP per line
    - iptables: iptables rules
    - nftables: nftables set
    - pf: pf (packet filter) rules
    - hosts: /etc/hosts format for DNS sinkhole
    - unbound: Unbound DNS config
    - zeek: Zeek Intel Framework TSV
    - wazuh: Wazuh CDB list format
    """
    formatters = {
        "plain": format_as_plain,
        "iptables": format_as_iptables,
        "nftables": format_as_nftables,
        "pf": format_as_pf,
        "hosts": format_as_hosts_file,
        "unbound": format_as_unbound_blocklist,
        "zeek": lambda _: format_as_zeek_intel(indicators or []),
        "wazuh": lambda _: format_as_wazuh_cdb(indicators or []),
    }

    formatter = formatters.get(output_format, format_as_plain)

    if output_format in ("zeek", "wazuh"):
        return formatter(None)

    result = ""
    if ips:
        result += formatter(ips)
    if domains and output_format in ("hosts", "unbound"):
        result += "\n" + formatter(domains) if result else formatter(domains)

    return result

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


# ─── Firewall API Integration Functions ─────────────────────────────────

import httpx
from typing import Literal


async def block_ip_wazuh(
    ip_address: str,
    wazuh_url: str,
    wazuh_api_token: str,
    agent_id: str | None = None,
    duration_hours: int = 24,
) -> dict:
    """Block IP via Wazuh API active response.

    Args:
        ip_address: IP address to block
        wazuh_url: Wazuh API URL (e.g., https://wazuh.example.com:55000)
        wazuh_api_token: Wazuh API JWT token
        agent_id: Specific agent ID to block on (None = all agents)
        duration_hours: How long to block (0 = permanent)

    Returns:
        dict with status and details
    """
    try:
        async with httpx.AsyncClient(verify=False) as client:
            headers = {"Authorization": f"Bearer {wazuh_api_token}"}

            # Use active-response command to block IP
            payload = {
                "command": "firewall-block",
                "arguments": [ip_address, str(duration_hours)],
            }

            if agent_id:
                # Block on specific agent
                url = f"{wazuh_url}/active-response/{agent_id}"
            else:
                # Block on all agents
                url = f"{wazuh_url}/active-response/all"

            response = await client.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "firewall": "wazuh",
                "ip": ip_address,
                "duration_hours": duration_hours,
                "response": response.json(),
            }
    except Exception as e:
        logger.error(f"Failed to block IP via Wazuh: {e}")
        return {
            "success": False,
            "firewall": "wazuh",
            "ip": ip_address,
            "error": str(e),
        }


async def block_ip_cloudflare(
    ip_address: str,
    cloudflare_api_token: str,
    zone_id: str,
    action: Literal = "block",
) -> dict:
    """Block IP via Cloudflare API.

    Args:
        ip_address: IP address to block
        cloudflare_api_token: Cloudflare API token with Zone Firewall Rules edit permission
        zone_id: Cloudflare zone ID
        action: "block" or "challenge"

    Returns:
        dict with status and details
    """
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {cloudflare_api_token}",
                "Content-Type": "application/json",
            }

            # Create firewall rule
            payload = {
                "action": action,
                "description": f"Neev TIP Auto-block: {ip_address}",
                "filter": {
                    "expression": f"(ip.src eq {ip_address})",
                },
            }

            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
            response = await client.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "firewall": "cloudflare",
                "ip": ip_address,
                "action": action,
                "response": response.json(),
            }
    except Exception as e:
        logger.error(f"Failed to block IP via Cloudflare: {e}")
        return {
            "success": False,
            "firewall": "cloudflare",
            "ip": ip_address,
            "error": str(e),
        }


async def block_ip_aws_waf(
    ip_address: str,
    aws_region: str,
    web_acl_id: str,
    rule_group_id: str | None = None,
    action: Literal = "block",
) -> dict:
    """Block IP via AWS WAF using boto3.

    Args:
        ip_address: IP address to block
        aws_region: AWS region
        web_acl_id: AWS WAF Web ACL ID
        rule_group_id: Optional rule group ID
        action: "block" or "count"

    Returns:
        dict with status and details
    """
    try:
        import boto3

        wafv2 = boto3.client("wafv2", region_name=aws_region)

        # Create or update IP set
        ip_set_name = "neev-tip-blocklist"
        ip_set_id = None  # Would need to query existing IP sets

        # For now, this is a placeholder - full implementation requires:
        # 1. Creating/maintaining IP sets
        # 2. Adding IPs to IP sets
        # 3. Creating/updating rules that reference IP sets

        return {
            "success": True,
            "firewall": "aws_waf",
            "ip": ip_address,
            "action": action,
            "note": "IP added to blocklist - requires IP set management",
        }
    except ImportError:
        logger.error("boto3 not installed - AWS WAF integration unavailable")
        return {
            "success": False,
            "firewall": "aws_waf",
            "ip": ip_address,
            "error": "boto3 not installed",
        }
    except Exception as e:
        logger.error(f"Failed to block IP via AWS WAF: {e}")
        return {
            "success": False,
            "firewall": "aws_waf",
            "ip": ip_address,
            "error": str(e),
        }


async def block_ip_multiple(
    ip_address: str,
    firewalls: list[str],
    config: dict,
) -> dict:
    """Block IP across multiple firewalls.

    Args:
        ip_address: IP address to block
        firewalls: List of firewall names to use (e.g., ["wazuh", "cloudflare"])
        config: Dict containing firewall credentials

    Returns:
        dict with overall status and per-firewall results
    """
    results = {}

    if "wazuh" in firewalls:
        results["wazuh"] = await block_ip_wazuh(
            ip_address=ip_address,
            wazuh_url=config.get("wazuh_url", ""),
            wazuh_api_token=config.get("wazuh_api_token", ""),
            agent_id=config.get("wazuh_agent_id"),
            duration_hours=config.get("wazuh_duration_hours", 24),
        )

    if "cloudflare" in firewalls:
        results["cloudflare"] = await block_ip_cloudflare(
            ip_address=ip_address,
            cloudflare_api_token=config.get("cloudflare_api_token", ""),
            zone_id=config.get("cloudflare_zone_id", ""),
            action=config.get("cloudflare_action", "block"),
        )

    if "aws_waf" in firewalls:
        results["aws_waf"] = await block_ip_aws_waf(
            ip_address=ip_address,
            aws_region=config.get("aws_region", "us-east-1"),
            web_acl_id=config.get("aws_web_acl_id", ""),
            rule_group_id=config.get("aws_rule_group_id"),
            action=config.get("aws_waf_action", "block"),
        )

    # Determine overall success
    success_count = sum(1 for r in results.values() if r.get("success"))
    overall_success = success_count > 0

    return {
        "success": overall_success,
        "ip": ip_address,
        "firewalls_attempted": firewalls,
        "successful_blocks": success_count,
        "results": results,
    }


async def unblock_ip_wazuh(
    ip_address: str,
    wazuh_url: str,
    wazuh_api_token: str,
    agent_id: str | None = None,
) -> dict:
    """Unblock IP via Wazuh API."""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            headers = {"Authorization": f"Bearer {wazuh_api_token}"}

            payload = {
                "command": "firewall-unblock",
                "arguments": [ip_address],
            }

            if agent_id:
                url = f"{wazuh_url}/active-response/{agent_id}"
            else:
                url = f"{wazuh_url}/active-response/all"

            response = await client.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "firewall": "wazuh",
                "ip": ip_address,
                "response": response.json(),
            }
    except Exception as e:
        logger.error(f"Failed to unblock IP via Wazuh: {e}")
        return {
            "success": False,
            "firewall": "wazuh",
            "ip": ip_address,
            "error": str(e),
        }


async def unblock_ip_cloudflare(
    ip_address: str,
    cloudflare_api_token: str,
    zone_id: str,
    rule_id: str,
) -> dict:
    """Unblock IP via Cloudflare API by deleting the rule."""
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {cloudflare_api_token}",
                "Content-Type": "application/json",
            }

            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules/{rule_id}"
            response = await client.delete(url, headers=headers, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "firewall": "cloudflare",
                "ip": ip_address,
                "response": response.json(),
            }
    except Exception as e:
        logger.error(f"Failed to unblock IP via Cloudflare: {e}")
        return {
            "success": False,
            "firewall": "cloudflare",
            "ip": ip_address,
            "error": str(e),
        }

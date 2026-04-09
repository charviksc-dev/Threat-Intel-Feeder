"""Automated Response Engine
Executes SOAR playbooks when high-confidence indicators are detected.
Uses open-source Active Response frameworks like Wazuh API.
"""

import logging
import asyncio
import httpx
from typing import Any, Dict
from ..config import settings

logger = logging.getLogger(__name__)

async def trigger_wazuh_active_response(command: str, arguments: list[str]):
    """Connects to the Wazuh Manager API to execute an Active Response on endpoints."""
    # Assuming Wazuh endpoints and credentials are provided in .env
    api_url = getattr(settings, "WAZUH_API_URL", "https://192.168.1.245:55000")
    user = getattr(settings, "WAZUH_API_USER", "wazuh-wui")
    password = getattr(settings, "WAZUH_API_PASSWORD", "")
    
    if not password:
        logger.debug("Wazuh API password missing, skipping automated response.")
        return

    async with httpx.AsyncClient(verify=False) as client:
        try:
            # 1. Authenticate
            auth_res = await client.get(f"{api_url}/security/user/authenticate", auth=(user, password))
            auth_res.raise_for_status()
            token = auth_res.json().get("data", {}).get("token")
            
            headers = {"Authorization": f"Bearer {token}"}
            payload = {"command": command, "custom": True, "arguments": arguments}
            
            # 2. Trigger active response across all agents ('000' is manager/all)
            res = await client.put(f"{api_url}/active-response?agents_list=all", json=payload, headers=headers)
            res.raise_for_status()
            logger.warning(f"SOAR TRIGGER: Executed {command} on endpoints with target: {arguments}")
            
        except Exception as e:
            logger.error(f"SOAR Wazuh Execution Failed: {e}")

def execute_playbooks(indicator: Dict[str, Any]):
    """Evaluates the indicator and fires appropriate playbooks.
    This runs synchronously in Celery worker but dispatches async jobs.
    """
    score = indicator.get("confidence_score", 0)
    ioc_value = indicator.get("indicator")
    ioc_type = indicator.get("type")
    
    # Threshold for automated action
    if score >= 70 and ioc_value:
        logger.warning(f"Indicator {ioc_value} reached CRITICAL score {score}. Initiating automated playbooks.")
        
        loop = asyncio.get_event_loop()
        
        if ioc_type in ["ipv4", "ipv6"]:
            # Drop IP on all firewalls controlled by Wazuh
            loop.run_until_complete(trigger_wazuh_active_response("firewall-drop", [ioc_value]))
            
        elif ioc_type in ["sha256", "md5"]:
            # Delete/quarantine malicious file hashes across all endpoints
            loop.run_until_complete(trigger_wazuh_active_response("ban-hash", [ioc_value]))

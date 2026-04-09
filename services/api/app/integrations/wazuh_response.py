"""Wazuh Active Response Integration
A free, open-source alternative to commercial EDRs. 
Uses the native Wazuh API to trigger active responses on agents.
- Ban hashes
- Firewall Drop IPs
- Restart services
"""

import logging
import httpx
from typing import Any, List, Dict
from ..config import settings

logger = logging.getLogger(__name__)

class WazuhResponseClient:
    def __init__(self):
        self.api_url = getattr(settings, "WAZUH_API_URL", "https://192.168.1.245:55000")
        self.api_user = getattr(settings, "WAZUH_API_USER", "wazuh-wui")
        self.api_password = getattr(settings, "WAZUH_API_PASSWORD", "")
        self.token = None

    async def authenticate(self) -> bool:
        if not self.api_password:
            logger.warning("Wazuh API password not configured.")
            return False
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                # Wazuh 4.x authentication
                response = await client.get(
                    f"{self.api_url}/security/user/authenticate",
                    auth=(self.api_user, self.api_password)
                )
                response.raise_for_status()
                self.token = response.json().get("data", {}).get("token")
                return True
            except Exception as e:
                logger.error(f"Failed to authenticate with Wazuh API: {e}")
                return False

    async def trigger_active_response(self, agent_id: str, command: str, arguments: List[str] = None) -> bool:
        """Triggers a central active response command on a specific agent."""
        if not self.token:
            if not await self.authenticate():
                return False

        payload = {
            "command": command,
            "custom": True,
            **({"arguments": arguments} if arguments else {})
        }

        async with httpx.AsyncClient(verify=False) as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                response = await client.put(
                    f"{self.api_url}/active-response?agents_list={agent_id}",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                logger.info(f"Successfully triggered {command} on agent {agent_id}. Target: {arguments}")
                return True
            except Exception as e:
                logger.error(f"Failed to trigger Wazuh Active Response: {e}")
                return False

    async def firewall_drop(self, agent_id: str, ip_to_drop: str) -> bool:
        """Uses Wazuh's native firewall-drop active response."""
        return await self.trigger_active_response(agent_id, "firewall-drop", [ip_to_drop])

    async def ban_hash(self, agent_id: str, file_hash: str) -> bool:
        """Uses a custom Wazuh script to quarantine a file by its hash locally."""
        return await self.trigger_active_response(agent_id, "ban-hash", [file_hash])


wazuh_responder = WazuhResponseClient()

async def block_on_wazuh(indicator_dict: Dict[str, Any], agent_id: str = "000"):
    """Helper method to push blocks to agents natively."""
    ioc_value = indicator_dict.get("indicator")
    original_type = indicator_dict.get("type", "")
    
    if original_type in ["ipv4", "ipv6"] and ioc_value:
        await wazuh_responder.firewall_drop(agent_id, ioc_value)
    elif original_type in ["sha256", "md5"] and ioc_value:
        await wazuh_responder.ban_hash(agent_id, ioc_value)

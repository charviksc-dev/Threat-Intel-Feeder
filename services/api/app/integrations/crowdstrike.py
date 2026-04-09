"""CrowdStrike Falcon Integration
Provides automated containment and IoC banning natively on enterprise endpoints.
"""

import logging
import httpx
from typing import Any, List, Dict
from ..config import settings

logger = logging.getLogger(__name__)

class CrowdStrikeClient:
    def __init__(self):
        self.client_id = getattr(settings, "CROWDSTRIKE_CLIENT_ID", None)
        self.client_secret = getattr(settings, "CROWDSTRIKE_CLIENT_SECRET", None)
        self.base_url = getattr(settings, "CROWDSTRIKE_API_URL", "https://api.crowdstrike.com")
        self.token = None

    async def authenticate(self) -> bool:
        if not self.client_id or not self.client_secret:
            logger.warning("CrowdStrike credentials not configured.")
            return False
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/oauth2/token",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret
                    }
                )
                response.raise_for_status()
                self.token = response.json().get("access_token")
                return True
            except Exception as e:
                logger.error(f"Failed to authenticate with CrowdStrike: {e}")
                return False

    async def ban_ioc(self, indicator: str, ioc_type: str, description: str) -> bool:
        """Uploads a hash, domain, or IP to Crowdstrike as a Custom IOC with 'block' action."""
        if not self.token:
            if not await self.authenticate():
                return False

        payload = {
            "indicators": [
                {
                    "action": "prevent",
                    "applied_globally": True,
                    "description": description,
                    "source": "Neev TIP Automation",
                    "type": ioc_type,  # e.g., 'sha256', 'domain', 'ipv4'
                    "value": indicator
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                response = await client.post(
                    f"{self.base_url}/indicators/entities/iocs/v1",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                logger.info(f"Successfully banned {ioc_type} IOC in CrowdStrike: {indicator}")
                return True
            except Exception as e:
                logger.error(f"Failed to ban IOC in CrowdStrike: {e}")
                return False

    async def network_contain_host(self, host_id: str) -> bool:
        """Isolates a compromised host from the network, allowing only portal communication."""
        if not self.token:
            if not await self.authenticate():
                return False

        payload = {
            "action_parameters": [{"name": "network_contain", "value": "true"}],
            "ids": [host_id]
        }

        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                response = await client.post(
                    f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                logger.warning(f"Successfully isolated host {host_id} via CrowdStrike.")
                return True
            except Exception as e:
                logger.error(f"Failed to contain host in CrowdStrike: {e}")
                return False

# Singleton instance
falcon_api = CrowdStrikeClient()

async def push_ioc_to_edr(indicator_dict: Dict[str, Any]):
    """Helper method to be called from the Correlator when a severe threat is found."""
    ioc_value = indicator_dict.get("indicator")
    original_type = indicator_dict.get("type", "")
    
    # Map Neev types to Crowdstrike types
    type_mapping = {
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "domain": "domain",
        "sha256": "sha256",
        "md5": "md5"
    }
    
    cs_type = type_mapping.get(original_type)
    if not cs_type or not ioc_value:
        return
        
    await falcon_api.ban_ioc(
        indicator=ioc_value,
        ioc_type=cs_type,
        description=f"Automated threat block by Neev TIP. Score: {indicator_dict.get('confidence_score')}"
    )

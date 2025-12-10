"""API client for CrowdStrike Falcon API."""
import httpx
import os
from typing import Optional, Dict, Any
from config import get_config


class APIClient:
    """Async HTTP client for CrowdStrike Falcon API."""
    
    def __init__(self, api_key: str, tenant_id: Optional[str] = None):
        """Initialize API client with credentials.
        
        Args:
            api_key: CrowdStrike API key (client_id)
            tenant_id: Optional tenant ID for multi-tenant scenarios
        """
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.base_url = get_config()["API_BASE_URL"]
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
    
    async def _get_auth_token(self) -> str:
        """Get OAuth2 token from CrowdStrike API.
        
        Note: CrowdStrike API keys can be provided in two formats:
        1. "client_id:client_secret" (combined format)
        2. Just "client_id" (if client_secret is provided separately)
        
        The API key parameter can also be set as an environment variable
        FALCON_CLIENT_SECRET if you want to separate them.
        
        Returns:
            Bearer token for API authentication
        """
        auth_url = f"{self.base_url}/oauth2/token"
        
        # Handle API key format - could be "client_id:client_secret" or just "client_id"
        if ":" in self.api_key:
            client_id, client_secret = self.api_key.split(":", 1)
        else:
            client_id = self.api_key
            # Try to get client_secret from environment or use api_key as fallback
            client_secret = os.getenv("FALCON_CLIENT_SECRET", self.api_key)
        
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                auth_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            token_data = response.json()
            return token_data.get("access_token", "")
    
    async def _get_headers(self) -> Dict[str, str]:
        """Get headers with authentication token."""
        token = await self._get_auth_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            headers["X-CS-TENANT-ID"] = self.tenant_id
        return headers
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request to API."""
        headers = await self._get_headers()
        response = await self.client.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make POST request to API."""
        headers = await self._get_headers()
        response = await self.client.post(endpoint, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    
    async def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make PUT request to API."""
        headers = await self._get_headers()
        response = await self.client.put(endpoint, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    
    async def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make DELETE request to API."""
        headers = await self._get_headers()
        response = await self.client.delete(endpoint, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()


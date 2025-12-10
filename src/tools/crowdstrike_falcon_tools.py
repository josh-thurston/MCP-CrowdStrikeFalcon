"""Tools (API functions) for CrowdStrike Falcon MCP Server."""
import os
from typing import Optional, Dict, Any, List
from ..client.api_client import APIClient
from .common import validate_api_key


def _get_api_key_from_env() -> Optional[str]:
    """Get API key from environment variable if available."""
    return os.getenv("FALCON_API_KEY") or os.getenv("CROWDSTRIKE_API_KEY")


def _get_tenant_id_from_env() -> Optional[str]:
    """Get tenant ID from environment variable if available."""
    return os.getenv("FALCON_TENANT_ID") or os.getenv("CROWDSTRIKE_TENANT_ID")


# Host/Device Tools
async def get_hosts(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query hosts/devices.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order (e.g., "hostname.asc")
        
    Returns:
        Dictionary containing hosts data
    """
    # Allow credentials from environment if not provided
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/devices/queries/devices/v1", params=params)
    finally:
        await client.close()


async def get_host_details(
    api_key: str,
    device_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information about specific hosts.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        device_ids: List of device IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing host details
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {"ids": ",".join(device_ids)}
        return await client.get("/devices/entities/devices/v2", params=params)
    finally:
        await client.close()


# Detection Tools
async def query_detections(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query detections.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing detections data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/detects/queries/detects/v1", params=params)
    finally:
        await client.close()


async def get_detection_details(
    api_key: str,
    detection_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information about specific detections.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        detection_ids: List of detection IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing detection details
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        data = {"ids": detection_ids}
        return await client.post("/detects/entities/summaries/GET/v1", data=data)
    finally:
        await client.close()


async def update_detections(
    api_key: str,
    detection_ids: List[str],
    status: str,
    tenant_id: Optional[str] = None,
    assigned_to_uuid: Optional[str] = None,
    comment: Optional[str] = None,
) -> Dict[str, Any]:
    """Update detection status.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        detection_ids: List of detection IDs to update
        status: New status (e.g., "new", "in_progress", "true_positive", "false_positive", "ignored")
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        assigned_to_uuid: Optional user UUID to assign detections to
        comment: Optional comment to add
        
    Returns:
        Dictionary containing update results
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        data = {
            "ids": detection_ids,
            "status": status,
        }
        if assigned_to_uuid:
            data["assigned_to_uuid"] = assigned_to_uuid
        if comment:
            data["comment"] = comment
        
        return await client.post("/detects/entities/detects/v2", data=data)
    finally:
        await client.close()


# IOC Tools
async def query_iocs(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query Indicators of Compromise (IOCs).
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing IOCs data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/iocs/queries/indicators/v1", params=params)
    finally:
        await client.close()


async def create_ioc(
    api_key: str,
    type: str,
    value: str,
    action: str,
    platforms: List[str],
    tenant_id: Optional[str] = None,
    severity: Optional[str] = None,
    description: Optional[str] = None,
    expiration: Optional[str] = None,
    applied_globally: Optional[bool] = False,
    host_groups: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a new Indicator of Compromise (IOC).
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        type: IOC type (e.g., "domain", "ipv4", "ipv6", "md5", "sha256")
        value: IOC value
        action: Action to take (e.g., "detect", "prevent", "allow")
        platforms: List of platforms (e.g., ["Windows", "Mac", "Linux"])
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        severity: Optional severity level
        description: Optional description
        expiration: Optional expiration date (ISO 8601 format)
        applied_globally: Whether to apply globally (default: False)
        host_groups: Optional list of host group IDs
        
    Returns:
        Dictionary containing created IOC data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        data = {
            "type": type,
            "value": value,
            "action": action,
            "platforms": platforms,
        }
        if severity:
            data["severity"] = severity
        if description:
            data["description"] = description
        if expiration:
            data["expiration"] = expiration
        if applied_globally is not None:
            data["applied_globally"] = applied_globally
        if host_groups:
            data["host_groups"] = host_groups
        
        return await client.post("/iocs/entities/indicators/v1", data=data)
    finally:
        await client.close()


async def delete_ioc(
    api_key: str,
    ioc_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Delete Indicators of Compromise (IOCs).
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        ioc_ids: List of IOC IDs to delete
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing deletion results
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {"ids": ",".join(ioc_ids)}
        return await client.delete("/iocs/entities/indicators/v1", params=params)
    finally:
        await client.close()


# Host Group Tools
async def query_host_groups(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query host groups.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing host groups data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/devices/queries/host-groups/v1", params=params)
    finally:
        await client.close()


async def get_host_group_details(
    api_key: str,
    group_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information about specific host groups.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        group_ids: List of host group IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing host group details
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {"ids": ",".join(group_ids)}
        return await client.get("/devices/entities/host-groups/v1", params=params)
    finally:
        await client.close()


# Prevention Policy Tools
async def query_prevention_policies(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query prevention policies.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing prevention policies data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/policy/queries/prevention/v1", params=params)
    finally:
        await client.close()


async def get_prevention_policy_details(
    api_key: str,
    policy_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information about specific prevention policies.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        policy_ids: List of prevention policy IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing prevention policy details
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {"ids": ",".join(policy_ids)}
        return await client.get("/policy/entities/prevention/v1", params=params)
    finally:
        await client.close()


# Sensor Update Policy Tools
async def query_sensor_update_policies(
    api_key: str,
    tenant_id: Optional[str] = None,
    filter: Optional[str] = None,
    limit: Optional[int] = 100,
    offset: Optional[int] = 0,
    sort: Optional[str] = None,
) -> Dict[str, Any]:
    """Query sensor update policies.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing sensor update policies data
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {}
        if filter:
            params["filter"] = filter
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        if sort:
            params["sort"] = sort
        
        return await client.get("/policy/queries/sensor-update/v1", params=params)
    finally:
        await client.close()


async def get_sensor_update_policy_details(
    api_key: str,
    policy_ids: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information about specific sensor update policies.
    
    Args:
        api_key: CrowdStrike API key (or use FALCON_API_KEY env var)
        policy_ids: List of sensor update policy IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or use FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing sensor update policy details
    """
    api_key = api_key or _get_api_key_from_env()
    tenant_id = tenant_id or _get_tenant_id_from_env()
    
    if not api_key:
        raise ValueError("api_key is required (or set FALCON_API_KEY environment variable)")
    
    if not validate_api_key(api_key):
        raise ValueError("Invalid API key format")
    
    client = APIClient(api_key, tenant_id)
    try:
        params = {"ids": ",".join(policy_ids)}
        return await client.get("/policy/entities/sensor-update/v2", params=params)
    finally:
        await client.close()


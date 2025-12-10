"""MCP Server for CrowdStrike Falcon using FastMCP."""
from fastmcp import FastMCP
from config import get_transport_mode, get_config
from src.tools import (
    get_hosts as get_hosts_tool,
    get_host_details as get_host_details_tool,
    query_detections as query_detections_tool,
    get_detection_details as get_detection_details_tool,
    update_detections as update_detections_tool,
    query_iocs as query_iocs_tool,
    create_ioc as create_ioc_tool,
    delete_ioc as delete_ioc_tool,
    query_host_groups as query_host_groups_tool,
    get_host_group_details as get_host_group_details_tool,
    query_prevention_policies as query_prevention_policies_tool,
    get_prevention_policy_details as get_prevention_policy_details_tool,
    query_sensor_update_policies as query_sensor_update_policies_tool,
    get_sensor_update_policy_details as get_sensor_update_policy_details_tool,
)

# Create FastMCP server instance
mcp = FastMCP("CrowdStrike Falcon MCP Server")


# Host/Device Tools
@mcp.tool()
async def query_hosts(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query hosts/devices in CrowdStrike Falcon.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string (e.g., "hostname:'example.com'")
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order (e.g., "hostname.asc")
        
    Returns:
        Dictionary containing hosts data with resources, meta, and errors
    """
    return await get_hosts_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def get_host_details(
    api_key: str,
    device_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Get detailed information about specific hosts/devices.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        device_ids: List of device IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing detailed host information
    """
    return await get_host_details_tool(api_key, device_ids, tenant_id)


# Detection Tools
@mcp.tool()
async def query_detections(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query detections in CrowdStrike Falcon.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string (e.g., "status:'new'")
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing detections data
    """
    return await query_detections_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def get_detection_details(
    api_key: str,
    detection_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Get detailed information about specific detections.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        detection_ids: List of detection IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing detailed detection information
    """
    return await get_detection_details_tool(api_key, detection_ids, tenant_id)


@mcp.tool()
async def update_detection_status(
    api_key: str,
    detection_ids: list[str],
    status: str,
    tenant_id: str | None = None,
    assigned_to_uuid: str | None = None,
    comment: str | None = None,
) -> dict:
    """Update detection status.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        detection_ids: List of detection IDs to update
        status: New status (e.g., "new", "in_progress", "true_positive", "false_positive", "ignored")
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        assigned_to_uuid: Optional user UUID to assign detections to
        comment: Optional comment to add
        
    Returns:
        Dictionary containing update results
    """
    return await update_detections_tool(api_key, detection_ids, status, tenant_id, assigned_to_uuid, comment)


# IOC Tools
@mcp.tool()
async def query_iocs(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query Indicators of Compromise (IOCs).
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing IOCs data
    """
    return await query_iocs_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def create_ioc(
    api_key: str,
    type: str,
    value: str,
    action: str,
    platforms: list[str],
    tenant_id: str | None = None,
    severity: str | None = None,
    description: str | None = None,
    expiration: str | None = None,
    applied_globally: bool = False,
    host_groups: list[str] | None = None,
) -> dict:
    """Create a new Indicator of Compromise (IOC).
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        type: IOC type (e.g., "domain", "ipv4", "ipv6", "md5", "sha256")
        value: IOC value
        action: Action to take (e.g., "detect", "prevent", "allow")
        platforms: List of platforms (e.g., ["Windows", "Mac", "Linux"])
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        severity: Optional severity level
        description: Optional description
        expiration: Optional expiration date (ISO 8601 format)
        applied_globally: Whether to apply globally (default: False)
        host_groups: Optional list of host group IDs
        
    Returns:
        Dictionary containing created IOC data
    """
    return await create_ioc_tool(
        api_key, type, value, action, platforms, tenant_id,
        severity, description, expiration, applied_globally, host_groups
    )


@mcp.tool()
async def delete_ioc(
    api_key: str,
    ioc_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Delete Indicators of Compromise (IOCs).
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        ioc_ids: List of IOC IDs to delete
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing deletion results
    """
    return await delete_ioc_tool(api_key, ioc_ids, tenant_id)


# Host Group Tools
@mcp.tool()
async def query_host_groups(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query host groups.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing host groups data
    """
    return await query_host_groups_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def get_host_group_details(
    api_key: str,
    group_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Get detailed information about specific host groups.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        group_ids: List of host group IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing host group details
    """
    return await get_host_group_details_tool(api_key, group_ids, tenant_id)


# Prevention Policy Tools
@mcp.tool()
async def query_prevention_policies(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query prevention policies.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing prevention policies data
    """
    return await query_prevention_policies_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def get_prevention_policy_details(
    api_key: str,
    policy_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Get detailed information about specific prevention policies.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        policy_ids: List of prevention policy IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing prevention policy details
    """
    return await get_prevention_policy_details_tool(api_key, policy_ids, tenant_id)


# Sensor Update Policy Tools
@mcp.tool()
async def query_sensor_update_policies(
    api_key: str,
    tenant_id: str | None = None,
    filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort: str | None = None,
) -> dict:
    """Query sensor update policies.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        filter: FQL filter string
        limit: Maximum number of results (1-5000, default: 100)
        offset: Offset for pagination (default: 0)
        sort: Sort order
        
    Returns:
        Dictionary containing sensor update policies data
    """
    return await query_sensor_update_policies_tool(api_key, tenant_id, filter, limit, offset, sort)


@mcp.tool()
async def get_sensor_update_policy_details(
    api_key: str,
    policy_ids: list[str],
    tenant_id: str | None = None,
) -> dict:
    """Get detailed information about specific sensor update policies.
    
    Args:
        api_key: CrowdStrike API key (or set FALCON_API_KEY env var)
        policy_ids: List of sensor update policy IDs to query
        tenant_id: Optional tenant ID for multi-tenant scenarios (or set FALCON_TENANT_ID env var)
        
    Returns:
        Dictionary containing sensor update policy details
    """
    return await get_sensor_update_policy_details_tool(api_key, policy_ids, tenant_id)


# Main entry point
if __name__ == "__main__":
    transport_mode = get_transport_mode()
    
    if transport_mode == "stdio":
        # STDIO mode only
        mcp.run()
    elif transport_mode == "http":
        # HTTP mode only - will be handled by http_gateway.py
        from src.http_gateway import create_http_app
        import uvicorn
        config = get_config()
        app = create_http_app(mcp)
        uvicorn.run(app, host="0.0.0.0", port=config["HTTP_PORT"])
    else:  # dual mode
        # Run both STDIO and HTTP
        # Note: In dual mode, you typically run STDIO in one process/container
        # and HTTP in another, or use a process manager like supervisord
        # For simplicity, we'll run HTTP in a background thread
        import uvicorn
        from src.http_gateway import create_http_app
        import threading
        
        config = get_config()
        
        def run_http():
            """Run HTTP server in background thread."""
            app = create_http_app(mcp)
            uvicorn.run(app, host="0.0.0.0", port=config["HTTP_PORT"], log_level="info")
        
        # Start HTTP server in background thread
        http_thread = threading.Thread(target=run_http, daemon=True)
        http_thread.start()
        
        # Run STDIO server in main thread
        mcp.run()


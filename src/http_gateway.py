"""HTTP Gateway layer for CrowdStrike Falcon MCP Server."""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional
from config import get_config
from src.mcp_server import mcp


def create_http_app(mcp_server) -> FastAPI:
    """Create FastAPI application that wraps the MCP server.
    
    Args:
        mcp_server: The FastMCP server instance
        
    Returns:
        FastAPI application instance
    """
    app = FastAPI(
        title="CrowdStrike Falcon MCP Server",
        description="HTTP/REST gateway for CrowdStrike Falcon MCP Server",
        version="1.0.0",
    )
    
    @app.get("/healthz")
    async def health_check():
        """Health check endpoint for orchestrators."""
        return {"status": "ok", "service": "crowdstrike-falcon-mcp"}
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "CrowdStrike Falcon MCP Server",
            "version": "1.0.0",
            "transport": "HTTP/REST",
            "endpoints": {
                "health": "/healthz",
                "tools": "/tools",
                "call_tool": "/tools/{tool_name}",
            },
            "documentation": "/docs",
        }
    
    @app.get("/tools")
    async def list_tools():
        """List all available MCP tools."""
        try:
            # Get tools from MCP server
            # Note: This is a simplified approach - you may need to adjust based on FastMCP API
            tools = []
            # In a real implementation, you'd query the MCP server for available tools
            # For now, we'll return a static list based on what we know
            known_tools = [
                "query_hosts",
                "get_host_details",
                "query_detections",
                "get_detection_details",
                "update_detection_status",
                "query_iocs",
                "create_ioc",
                "delete_ioc",
                "query_host_groups",
                "get_host_group_details",
                "query_prevention_policies",
                "get_prevention_policy_details",
                "query_sensor_update_policies",
                "get_sensor_update_policy_details",
            ]
            return {
                "tools": [
                    {
                        "name": tool_name,
                        "description": f"Execute {tool_name} tool",
                        "endpoint": f"/tools/{tool_name}",
                    }
                    for tool_name in known_tools
                ]
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/tools/{tool_name}")
    async def call_tool(tool_name: str, request: Request):
        """Call an MCP tool by name.
        
        Args:
            tool_name: Name of the tool to call
            request: FastAPI request object containing JSON body with tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            body = await request.json()
            
            # Extract api_key and tenant_id from body or headers
            api_key = body.get("api_key") or request.headers.get("X-API-Key")
            tenant_id = body.get("tenant_id") or request.headers.get("X-Tenant-ID")
            
            if not api_key:
                raise HTTPException(
                    status_code=400,
                    detail="api_key is required (provide in request body or X-API-Key header)"
                )
            
            # Remove api_key and tenant_id from body to pass remaining params to tool
            tool_params = {k: v for k, v in body.items() if k not in ["api_key", "tenant_id"]}
            if tenant_id:
                tool_params["tenant_id"] = tenant_id
            
            # Import and call tools directly
            from src.tools import (
                get_hosts,
                get_host_details,
                query_detections as query_detections_func,
                get_detection_details as get_detection_details_func,
                update_detections,
                query_iocs as query_iocs_func,
                create_ioc as create_ioc_func,
                delete_ioc as delete_ioc_func,
                query_host_groups as query_host_groups_func,
                get_host_group_details as get_host_group_details_func,
                query_prevention_policies as query_prevention_policies_func,
                get_prevention_policy_details as get_prevention_policy_details_func,
                query_sensor_update_policies as query_sensor_update_policies_func,
                get_sensor_update_policy_details as get_sensor_update_policy_details_func,
            )
            
            tool_func_map = {
                "query_hosts": get_hosts,
                "get_host_details": get_host_details,
                "query_detections": query_detections_func,
                "get_detection_details": get_detection_details_func,
                "update_detection_status": update_detections,
                "query_iocs": query_iocs_func,
                "create_ioc": create_ioc_func,
                "delete_ioc": delete_ioc_func,
                "query_host_groups": query_host_groups_func,
                "get_host_group_details": get_host_group_details_func,
                "query_prevention_policies": query_prevention_policies_func,
                "get_prevention_policy_details": get_prevention_policy_details_func,
                "query_sensor_update_policies": query_sensor_update_policies_func,
                "get_sensor_update_policy_details": get_sensor_update_policy_details_func,
            }
            
            if tool_name not in tool_func_map:
                raise HTTPException(
                    status_code=404,
                    detail=f"Tool '{tool_name}' not found. Available tools: {list(tool_func_map.keys())}"
                )
            
            tool_func = tool_func_map[tool_name]
            
            # Add api_key to params
            tool_params["api_key"] = api_key
            
            # Call the tool function
            result = await tool_func(**tool_params)
            
            return JSONResponse(content=result)
            
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Tool execution error: {str(e)}")
    
    return app


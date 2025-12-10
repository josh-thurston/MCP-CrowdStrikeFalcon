"""Configuration management for CrowdStrike Falcon MCP Server."""
import os
from typing import Literal

TransportMode = Literal["stdio", "http", "dual"]


def get_config() -> dict:
    """Get configuration from environment variables with defaults."""
    return {
        "API_BASE_URL": os.getenv("FALCON_API_BASE_URL", "https://api.crowdstrike.com"),
        "TRANSPORT_MODE": os.getenv("TRANSPORT_MODE", "dual").lower(),
        "HTTP_PORT": int(os.getenv("HTTP_PORT", "80")),
        "STDIO_PORT": int(os.getenv("STDIO_PORT", "8080")),
    }


def get_transport_mode() -> TransportMode:
    """Get the transport mode, validating it's one of the allowed values."""
    mode = get_config()["TRANSPORT_MODE"]
    if mode not in ["stdio", "http", "dual"]:
        return "dual"
    return mode  # type: ignore


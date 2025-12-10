"""Common utilities for CrowdStrike Falcon tools."""


def validate_api_key(api_key: str) -> bool:
    """Validate API key format (basic validation).
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if key appears valid, False otherwise
    """
    if not api_key or not isinstance(api_key, str):
        return False
    # Basic validation - API keys are typically 32+ character strings
    # Adjust this based on actual CrowdStrike API key format
    return len(api_key.strip()) >= 16


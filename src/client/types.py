"""Pydantic models for CrowdStrike Falcon API requests and responses."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class Error(BaseModel):
    """API error response model."""
    code: int
    message: str
    id: Optional[str] = None


class MetaInfo(BaseModel):
    """Metadata information in API responses."""
    pagination: Optional[Dict[str, Any]] = None
    query_time: Optional[float] = None
    trace_id: Optional[str] = None
    powered_by: Optional[str] = None


class BaseResponse(BaseModel):
    """Base response model for all API responses."""
    errors: Optional[List[Error]] = None
    meta: Optional[MetaInfo] = None
    resources: Optional[List[Dict[str, Any]]] = None


# Host/Device Models
class Host(BaseModel):
    """Host/device model."""
    device_id: str
    hostname: Optional[str] = None
    local_ip: Optional[str] = None
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    platform_name: Optional[str] = None
    status: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class HostResponse(BaseResponse):
    """Response model for host queries."""
    resources: Optional[List[Host]] = None


# Detection Models
class Detection(BaseModel):
    """Detection model."""
    detection_id: str
    device_id: Optional[str] = None
    hostname: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    first_behavior: Optional[str] = None
    max_severity: Optional[str] = None
    max_confidence: Optional[str] = None


class DetectionResponse(BaseResponse):
    """Response model for detection queries."""
    resources: Optional[List[Detection]] = None


# IOC Models
class IOC(BaseModel):
    """Indicator of Compromise model."""
    id: str
    type: str
    value: str
    action: Optional[str] = None
    platforms: Optional[List[str]] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    expiration: Optional[str] = None


class IOCResponse(BaseResponse):
    """Response model for IOC queries."""
    resources: Optional[List[IOC]] = None


class IOCCreateRequest(BaseModel):
    """Request model for creating IOCs."""
    type: str
    value: str
    action: str
    platforms: List[str]
    severity: Optional[str] = None
    description: Optional[str] = None
    expiration: Optional[str] = None
    applied_globally: Optional[bool] = False
    host_groups: Optional[List[str]] = None


# Incident Models
class Incident(BaseModel):
    """Incident model."""
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    created_date: Optional[str] = None
    updated_date: Optional[str] = None


class IncidentResponse(BaseResponse):
    """Response model for incident queries."""
    resources: Optional[List[Incident]] = None


# Host Group Models
class HostGroup(BaseModel):
    """Host group model."""
    id: str
    name: str
    description: Optional[str] = None
    group_type: Optional[str] = None
    assignment_rule: Optional[str] = None


class HostGroupResponse(BaseResponse):
    """Response model for host group queries."""
    resources: Optional[List[HostGroup]] = None


# Prevention Policy Models
class PreventionPolicy(BaseModel):
    """Prevention policy model."""
    id: str
    name: str
    description: Optional[str] = None
    enabled: bool
    platform_name: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None


class PreventionPolicyResponse(BaseResponse):
    """Response model for prevention policy queries."""
    resources: Optional[List[PreventionPolicy]] = None


# Sensor Update Policy Models
class SensorUpdatePolicy(BaseModel):
    """Sensor update policy model."""
    id: str
    name: str
    description: Optional[str] = None
    enabled: bool
    platform_name: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None


class SensorUpdatePolicyResponse(BaseResponse):
    """Response model for sensor update policy queries."""
    resources: Optional[List[SensorUpdatePolicy]] = None


# Real-Time Response Models
class RTRCommand(BaseModel):
    """Real-Time Response command model."""
    command_id: Optional[str] = None
    device_id: str
    command: str
    base_command: Optional[str] = None
    command_string: Optional[str] = None
    full_command: Optional[str] = None


class RTRCommandResponse(BaseResponse):
    """Response model for RTR commands."""
    resources: Optional[List[RTRCommand]] = None


# Query Parameters
class QueryParams(BaseModel):
    """Base query parameters model."""
    filter: Optional[str] = None
    limit: Optional[int] = Field(default=100, ge=1, le=5000)
    offset: Optional[int] = Field(default=0, ge=0)
    sort: Optional[str] = None


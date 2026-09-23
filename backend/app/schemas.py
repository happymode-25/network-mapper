"""Pydantic request/response schemas for the API."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


# --- Target ---
class TargetBase(BaseModel):
    ip: str = Field(..., description="IP address or wildcard to verify")
    hostname: Optional[str] = None


class TargetCreate(TargetBase):
    asset_id: Optional[int] = None


class TargetOut(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    authorized: bool
    created_at: datetime


class TargetPage(BaseModel):
    items: List[TargetOut]
    total: int
    page: int
    size: int


# --- Scan ---
class ScanCreate(BaseModel):
    target_id: int
    ports_to_scan: Optional[str] = Field(
        default=None,
        description="Optional comma-separated ports or ranges (e.g. '22,80-82,443'). "
        "Defaults to the built-in port list when omitted.",
    )


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: str
    requested_ports: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanPage(BaseModel):
    items: List[ScanOut]
    total: int
    page: int
    size: int


# --- Port / Service / Finding ---
class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service: Optional[ServiceOut] = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    service_id: Optional[int] = None
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    kev: bool
    description: Optional[str] = None
    remediation: Optional[str] = None
    confidence: str
    risk_score: Optional[float] = None


class ScanDetail(BaseModel):
    id: int
    status: str
    requested_ports: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    target: TargetOut
    ports: List[PortOut]
    findings: List[FindingOut]


class FindingPage(BaseModel):
    items: List[FindingOut]
    total: int
    page: int
    size: int


# --- Compare ---
class CompareItem(BaseModel):
    cve_id: str
    severity: str
    risk_score: Optional[float] = None
    confidence: str
    service: Optional[str] = None
    version: Optional[str] = None


class CompareResult(BaseModel):
    added: List[CompareItem]
    removed: List[CompareItem]
    changed: List[CompareItem]
    added_count: int
    removed_count: int
    changed_count: int


# --- Asset ---
class AssetCreate(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    importance: str = "low"
    owner: Optional[str] = None
    tags: Optional[str] = None


class AssetUpdate(BaseModel):
    importance: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[str] = None


class AssetOut(AssetCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int


class AssetPage(BaseModel):
    items: List[AssetOut]
    total: int
    page: int
    size: int
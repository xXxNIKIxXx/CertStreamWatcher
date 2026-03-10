"""Pydantic models for API request / response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class CertificateOut(BaseModel):
    """Single certificate record returned by the API."""

    id: Optional[str] = None   # UUID in ClickHouse
    log: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None
    dns_names: Optional[List[str]] = None
    fingerprint_sha256: Optional[str] = None
    ts: Optional[datetime] = None
    ct_entry_type: Optional[str] = None
    format: Optional[str] = None

    class Config:
        from_attributes = True


class PaginationMeta(BaseModel):
    """Pagination metadata included in list responses."""

    page: int
    page_size: int
    total: int
    total_pages: int


class CertificateListResponse(BaseModel):
    """Paginated list of certificates."""

    data: List[CertificateOut]
    meta: PaginationMeta


class StatsResponse(BaseModel):
    """Summary statistics for the certificate database."""

    total_certificates: int = 0
    unique_issuers: int = 0
    unique_subjects: int = 0
    earliest_cert: Optional[datetime] = None
    latest_cert: Optional[datetime] = None
    certs_last_hour: int = 0
    certs_last_24h: int = 0


class IssuerCount(BaseModel):
    issuer: str
    count: int


class TopIssuersResponse(BaseModel):
    data: List[IssuerCount]


class HealthResponse(BaseModel):
    status: str
    database: str
    version: str = "1.0.0"


class TimeseriesPoint(BaseModel):
    bucket: datetime
    count: int


class TimeseriesResponse(BaseModel):
    data: List[TimeseriesPoint]
    interval: str


class EnrichmentResponse(BaseModel):
    query: str
    certificate: Optional[CertificateOut] = None
    enrichment: Optional[dict] = None  # Add enrichment fields as needed
    ip_matches: Optional[list] = None  # List of certs matching IP, if searched by IP

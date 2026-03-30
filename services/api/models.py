"""Pydantic models for API request / response schemas."""
from typing import List, Optional, Any

from pydantic import BaseModel, Field, AnyUrl, EmailStr
from datetime import datetime


class CTLogOperatorModel(BaseModel):
    id: str
    name: Optional[str]
    email: Optional[EmailStr]
    added_at: Optional[datetime]

    class Config:
        from_attributes = True


class CTLogModel(BaseModel):
    id: str
    operator_id: Optional[str]
    description: Optional[str]
    log_id: Optional[str]
    key: Optional[str]
    url: Optional[AnyUrl]
    mmd: Optional[int]
    state: Optional[str]
    temporal_interval_start: Optional[datetime]
    temporal_interval_end: Optional[datetime]
    status: Optional[str]
    is_tiled: Optional[bool]
    submission_url: Optional[AnyUrl]
    monitoring_url: Optional[AnyUrl]
    added_at: Optional[datetime]

    class Config:
        from_attributes = True

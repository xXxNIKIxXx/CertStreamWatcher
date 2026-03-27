"""Pydantic models for API request / response schemas."""

from __future__ import annotations

from typing import List, Optional, Any

from pydantic import BaseModel, Field


# Pydantic models for filter rules and settings
class FilterRule(BaseModel):
    field: str
    op: str
    value: Any
    enabled: Optional[bool] = True


class FilterSettings(BaseModel):
    default_action: str = Field(..., pattern="^(allow|deny)$")
    filters: List[FilterRule] = []

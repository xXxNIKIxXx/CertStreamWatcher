"""
filters.py - REST API endpoints for managing filter rules and default mode.
"""
from __future__ import annotations


from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Any
from ..main import db
from services.shared.models import CTSetting
from sqlalchemy import select, insert, desc
import json

router = APIRouter(prefix="/filters", tags=["Filters"])

SETTINGS_KEY = "settings"

# Pydantic models for filter rules and settings


class FilterRule(BaseModel):
    field: str
    op: str
    value: Any
    enabled: Optional[bool] = True



class FilterSettings(BaseModel):
    default_action: str = Field(..., pattern="^(allow|deny)$")
    filters: List[FilterRule] = []

# Utility to load current settings from DB


async def get_current_settings() -> FilterSettings:
    # Build SQLAlchemy select for latest setting
    stmt = (
        select(CTSetting.value)
        .where(CTSetting.key == SETTINGS_KEY)
        .order_by(desc(CTSetting.ts))
        .limit(1)
    )
    compiled = stmt.compile(compile_kwargs={"literal_binds": True})
    result = await db._client.query(str(compiled))
    rows = result.result_rows if hasattr(result, 'result_rows') else result
    if not rows or not rows[0]:
        return FilterSettings(default_action="allow", filters=[])
    try:
        data = json.loads(rows[0][0])
        return FilterSettings(**data)
    except Exception:
        return FilterSettings(default_action="allow", filters=[])

# Utility to persist settings


async def save_settings(settings: FilterSettings):
    # Build SQLAlchemy insert for CTSetting
    stmt = insert(CTSetting).values(key=SETTINGS_KEY, value=settings.json())
    compiled = stmt.compile(compile_kwargs={"literal_binds": True})
    await db._client.command(str(compiled))

# List all filters and current mode


@router.get("", response_model=FilterSettings)
async def get_filters():
    return await get_current_settings()

# Add a filter


@router.post("", response_model=FilterSettings)
async def add_filter(rule: FilterRule):
    settings = await get_current_settings()
    settings.filters.append(rule)
    await save_settings(settings)
    return settings

# Update a filter by index


@router.put("/{index}", response_model=FilterSettings)
async def update_filter(index: int, rule: FilterRule):
    settings = await get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    settings.filters[index] = rule
    await save_settings(settings)
    return settings

# Delete a filter by index


@router.delete("/{index}", response_model=FilterSettings)
async def delete_filter(index: int):
    settings = await get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    settings.filters.pop(index)
    await save_settings(settings)
    return settings

# Enable/disable a filter by index


@router.patch("/{index}/toggle", response_model=FilterSettings)
async def toggle_filter(index: int):
    settings = await get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    rule = settings.filters[index]
    rule.enabled = not rule.enabled if rule.enabled is not None else False
    settings.filters[index] = rule
    await save_settings(settings)
    return settings

# Change default mode (block all / allow all)


@router.patch("/default_action", response_model=FilterSettings)
async def set_default_action(action: str = Query(..., pattern="^(allow|deny)$")):
    settings = await get_current_settings()
    settings.default_action = action
    await save_settings(settings)
    return settings

"""
filters.py - REST API endpoints for managing filter rules and default mode.
"""
from __future__ import annotations


from fastapi import APIRouter, HTTPException, Query
from ..models import FilterRule, FilterSettings
from ..util.filters import get_current_settings, save_settings

router = APIRouter(prefix="/filters", tags=["Filters"])

# List all filters and current mode


@router.get("", response_model=FilterSettings)
def get_filters():
    return get_current_settings()

# Add a filter


@router.post("", response_model=FilterSettings)
def add_filter(rule: FilterRule):
    settings = get_current_settings()
    settings.filters.append(rule)
    save_settings(settings)
    return settings

# Update a filter by index


@router.put("/{index}", response_model=FilterSettings)
def update_filter(index: int, rule: FilterRule):
    settings = get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    settings.filters[index] = rule
    save_settings(settings)
    return settings

# Delete a filter by index


@router.delete("/{index}", response_model=FilterSettings)
def delete_filter(index: int):
    settings = get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    settings.filters.pop(index)
    save_settings(settings)
    return settings

# Enable/disable a filter by index


@router.patch("/{index}/toggle", response_model=FilterSettings)
def toggle_filter(index: int):
    settings = get_current_settings()
    if index < 0 or index >= len(settings.filters):
        raise HTTPException(status_code=404, detail="Filter not found")
    rule = settings.filters[index]
    rule.enabled = not rule.enabled if rule.enabled is not None else False
    settings.filters[index] = rule
    save_settings(settings)
    return settings

# Change default mode (block all / allow all)


@router.patch("/default_action", response_model=FilterSettings)
async def set_default_action(action: str = Query(..., pattern="^(allow|deny)$")):
    settings = await get_current_settings()
    settings.default_action = action
    await save_settings(settings)
    return settings

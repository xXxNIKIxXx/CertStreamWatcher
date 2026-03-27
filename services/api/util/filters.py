from ..models import FilterSettings
from services.shared.models import CTSetting
from sqlalchemy import select, insert, desc
import json
from ..main import db


SETTINGS_KEY = "settings"


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
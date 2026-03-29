from ..models import FilterSettings
from services.shared.models import CTSetting
from sqlalchemy import select, desc
import json

from services.api.db_session import SessionLocal


SETTINGS_KEY = "settings"


# Utility to load current settings from DB


def get_current_settings() -> FilterSettings:
    with SessionLocal() as session:
        result = session.execute(
            select(CTSetting.value)
            .where(CTSetting.key == SETTINGS_KEY)
            .order_by(desc(CTSetting.ts))
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if not row:
            return FilterSettings(default_action="allow", filters=[])
        try:
            data = json.loads(row)
            return FilterSettings(**data)
        except Exception:
            return FilterSettings(default_action="allow", filters=[])

# Utility to persist settings


def save_settings(settings: FilterSettings):
    with SessionLocal() as session:
        obj = CTSetting(key=SETTINGS_KEY, value=settings.json())
        session.add(obj)
        session.commit()
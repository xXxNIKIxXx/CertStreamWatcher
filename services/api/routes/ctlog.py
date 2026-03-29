from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from services.shared.models import CTLog
from services.api.db_session import SessionLocal
from sqlalchemy.future import select

from ..util.mutation_guard import mutation_guard

# CTLog endpoints
router = APIRouter(prefix="/ctlog", tags=["CTLog"])



class CTLogModel(BaseModel):
    id: str
    operator_id: Optional[str]
    description: Optional[str]
    log_id: Optional[str]
    key: Optional[str]
    url: Optional[str]
    mmd: Optional[int]
    state: Optional[str]
    temporal_interval_start: Optional[datetime]
    temporal_interval_end: Optional[datetime]
    status: Optional[str]
    is_tiled: Optional[bool]
    submission_url: Optional[str]
    monitoring_url: Optional[str]
    added_at: Optional[datetime]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[CTLogModel])
def list_ctlogs():
    with SessionLocal() as session:
        result = session.execute(select(CTLog))
        return result.scalars().all()


@router.post("/", response_model=CTLogModel)
@mutation_guard
def add_ctlog(item: CTLogModel):
    with SessionLocal() as session:
        obj = CTLog(**item.dict())
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj


@router.put("/{id}", response_model=CTLogModel)
@mutation_guard
def edit_ctlog(id: str, item: CTLogModel):
    with SessionLocal() as session:
        result = session.execute(select(CTLog).where(CTLog.id == id))
        obj = result.scalar_one_or_none()
        if not obj:
            raise HTTPException(status_code=404, detail="Not found")
        for k, v in item.dict(exclude_unset=True).items():
            setattr(obj, k, v)
        session.commit()
        session.refresh(obj)
        return obj


@router.delete("/{id}")
@mutation_guard
def delete_ctlog(id: str):
    with SessionLocal() as session:
        result = session.execute(select(CTLog).where(CTLog.id == id))
        obj = result.scalar_one_or_none()
        if not obj:
            raise HTTPException(status_code=404, detail="Not found")
        session.delete(obj)
        session.commit()
        return {"ok": True}

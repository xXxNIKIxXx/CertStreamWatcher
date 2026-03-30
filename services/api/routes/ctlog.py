from fastapi import APIRouter, HTTPException
from typing import List
from services.shared.models import CTLog
from services.api.db_session import SessionLocal
from sqlalchemy.future import select

from ..models import CTLogModel
from ..util.mutation_guard import mutation_guard

# CTLog endpoints
router = APIRouter(prefix="/ctlog", tags=["CTLog"])

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

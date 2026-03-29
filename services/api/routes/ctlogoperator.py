from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from services.shared.models import CTLogOperator
from datetime import datetime
from services.api.db_session import SessionLocal
from sqlalchemy.future import select

from ..util.mutation_guard import mutation_guard

router = APIRouter(prefix="/ctlogoperator", tags=["CTLogOperator"])


class CTLogOperatorModel(BaseModel):
    id: str
    name: Optional[str]
    email: Optional[str]
    added_at: Optional[datetime]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[CTLogOperatorModel])
def list_ctlog_operators():
    with SessionLocal() as session:
        result = session.execute(select(CTLogOperator))
        return result.scalars().all()


@router.post("/", response_model=CTLogOperatorModel)
@mutation_guard
def add_ctlog_operator(item: CTLogOperatorModel):
    with SessionLocal() as session:
        obj = CTLogOperator(**item.dict())
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj


@router.put("/{id}", response_model=CTLogOperatorModel)
@mutation_guard
def edit_ctlog_operator(id: str, item: CTLogOperatorModel):
    with SessionLocal() as session:
        result = session.execute(select(CTLogOperator).where(CTLogOperator.id == id))
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
def delete_ctlog_operator(id: str):
    with SessionLocal() as session:
        result = session.execute(select(CTLogOperator).where(CTLogOperator.id == id))
        obj = result.scalar_one_or_none()
        if not obj:
            raise HTTPException(status_code=404, detail="Not found")
        session.delete(obj)
        session.commit()
        return {"ok": True}

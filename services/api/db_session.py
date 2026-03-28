from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from services.shared.models import Base
from services.api.config import DB_DSN

# Create SQLAlchemy engine for ClickHouse
engine = create_engine(DB_DSN, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# Ensure tables exist (optional, for dev)
Base.metadata.create_all(engine)


from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()


class CTLog(Base):
	"""
	SQLAlchemy model for ct_logs table, matching the web app/database schema exactly.
	Progress fields moved to CTLogSlice.
	"""
	__tablename__ = 'ct_logs'
	id = Column(String, primary_key=True)
	operator_id = Column(String)
	description = Column(String)
	log_id = Column(String)
	key = Column(String)
	url = Column(String)
	mmd = Column(Integer)
	state = Column(String)
	temporal_interval_start = Column(String)
	temporal_interval_end = Column(String)
	status = Column(String)
	is_tiled = Column(Boolean, default=False)
	submission_url = Column(String)
	monitoring_url = Column(String)
	added_at = Column(String, default=lambda: datetime.datetime.utcnow().isoformat(sep=' '))

	def __repr__(self):
		return (
			f"<CTLog(id={self.id}, url={self.url}, is_tiled={self.is_tiled})>"
		)


class CTLogSlice(Base):
	"""
	Tracks progress for a sub-range [slice_start, slice_end) of a CT log.

	One row per (log_id, slice_start).  In ClickHouse the table uses
	ReplacingMergeTree(updated_at) so every "update" is just an INSERT and
	the engine deduplicates during background merges – no unbounded growth.

	status: 'pending' | 'active' | 'done'
	worker_id: which worker/task owns this slice (for future sharding)
	"""
	__tablename__ = 'ct_log_slices'
	id            = Column(String,  primary_key=True)   # log id (FK → ct_logs.id)
	slice_start   = Column(Integer, primary_key=True)   # inclusive
	slice_end     = Column(Integer)                     # exclusive
	current_index = Column(Integer)
	worker_id     = Column(String,  default="")
	status        = Column(String,  default="pending")  # pending / active / done
	updated_at    = Column(DateTime, default=datetime.datetime.utcnow)

	def __repr__(self):
		return (
			f"<CTLogSlice(id={self.id}, "
			f"[{self.slice_start}-{self.slice_end}), "
			f"current={self.current_index}, status={self.status})>"
		)


class CTLogSource(Base):
	__tablename__ = 'ct_log_sources'
	id                = Column(String,  primary_key=True)
	url               = Column(String)
	name              = Column(String)
	enabled           = Column(Boolean)
	added_at          = Column(DateTime)
	last_polled       = Column(DateTime)
	backlog           = Column(Integer)
	freshness_seconds = Column(Integer)
	error_count       = Column(Integer)
	status            = Column(String)
	is_tiled          = Column(Boolean, default=False)


class CTLogOperator(Base):
	__tablename__ = 'ct_log_operators'
	id       = Column(String,   primary_key=True)
	name     = Column(String)
	email    = Column(String)
	added_at = Column(DateTime)


class CTCert(Base):
	__tablename__ = 'ct_certs'
	id                 = Column(String,   primary_key=True)
	log                = Column(String)
	subject            = Column(String)
	issuer             = Column(String)
	not_before         = Column(DateTime)
	not_after          = Column(DateTime)
	serial_number      = Column(String)
	dns_names          = Column(String)
	fingerprint_sha256 = Column(String)
	ct_entry_type      = Column(String)
	format             = Column(String)
	scripting_score    = Column(Integer, default=0)
	ts                 = Column(DateTime, default=datetime.datetime.utcnow)


class CTSetting(Base):
	__tablename__ = 'ct_settings'
	key   = Column(String,   primary_key=True)
	value = Column(String)
	ts    = Column(DateTime, default=datetime.datetime.utcnow)

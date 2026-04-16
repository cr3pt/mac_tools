from sqlalchemy.orm import declarative_base, Mapped, mapped_column
from sqlalchemy import String, Integer, Text, DateTime
Base = declarative_base()
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50))
class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"
    session_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    sample_name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(64))
    assignee: Mapped[str] = mapped_column(String(120), nullable=True)
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    static_score: Mapped[int] = mapped_column(Integer)
    dynamic_score: Mapped[int] = mapped_column(Integer)
    mitre_json: Mapped[str] = mapped_column(Text)
    iocs_json: Mapped[str] = mapped_column(Text)
    findings_json: Mapped[str] = mapped_column(Text)
    events_json: Mapped[str] = mapped_column(Text)
    meta_json: Mapped[str] = mapped_column(Text)
class JobRecord(Base):
    __tablename__ = "job_records"
    job_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    celery_id: Mapped[str] = mapped_column(String(255))
    trace_id: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[DateTime] = mapped_column(DateTime)

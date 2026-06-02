import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, Boolean, Float, DateTime, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status = Column(String(20), nullable=False, default="pending")

    url = Column(Text, nullable=False)
    filename = Column(String(255), nullable=True)

    malware = Column(Boolean, nullable=True)
    reason = Column(String(255), nullable=True)
    scan_duration = Column(Float, nullable=True)
    error = Column(Text, nullable=True)

    webhook_url = Column(Text, nullable=True)
    webhook_sent = Column(Boolean, default=False)
    metadata_ = Column("metadata", JSON, nullable=True)

    requested_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self):
        result = {
            "job_id": self.id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if self.status in ("done", "error"):
            result["malware"] = self.malware
            result["reason"] = self.reason
            result["time"] = self.scan_duration
            result["filename"] = self.filename
            result["completed_at"] = self.completed_at.isoformat() if self.completed_at else None
        if self.status == "error":
            result["error"] = self.error
        return result

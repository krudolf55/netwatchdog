"""SQLAlchemy ORM models for all netwatchdog tables."""

from __future__ import annotations

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Host(Base):  # type: ignore[misc]
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(Text, nullable=False, unique=True)
    hostname = Column(Text)
    label = Column(Text)
    active = Column(Integer, nullable=False, default=1)
    source = Column(Text, nullable=False, default="cli")  # 'config' or 'cli'
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    port_states = relationship("PortState", back_populates="host", cascade="all, delete-orphan")
    port_history = relationship("PortHistory", back_populates="host", cascade="all, delete-orphan")
    change_events = relationship("ChangeEvent", back_populates="host", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Host(id={self.id}, ip={self.ip_address}, label={self.label})>"


class ScanJob(Base):  # type: ignore[misc]
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(Text, nullable=False)
    status = Column(Text, nullable=False)
    triggered_by = Column(Text, nullable=False, default="scheduler")
    started_at = Column(Text)
    completed_at = Column(Text)
    hosts_scanned = Column(Integer)
    ports_scanned = Column(Text)  # JSON string
    error_message = Column(Text)
    created_at = Column(Text, nullable=False)

    port_states = relationship("PortState", back_populates="scan_job")
    port_history = relationship("PortHistory", back_populates="scan_job")
    change_events = relationship("ChangeEvent", back_populates="scan_job")

    def __repr__(self) -> str:
        return f"<ScanJob(id={self.id}, type={self.scan_type}, status={self.status})>"


class PortState(Base):  # type: ignore[misc]
    __tablename__ = "port_states"
    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Text, nullable=False, default="tcp")
    state = Column(Text, nullable=False)
    service_name = Column(Text)
    service_info = Column(Text)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    last_seen_at = Column(Text, nullable=False)

    host = relationship("Host", back_populates="port_states")
    scan_job = relationship("ScanJob", back_populates="port_states")

    def __repr__(self) -> str:
        return f"<PortState(host_id={self.host_id}, port={self.port}, state={self.state})>"


class PortHistory(Base):  # type: ignore[misc]
    __tablename__ = "port_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Text, nullable=False, default="tcp")
    state = Column(Text, nullable=False)
    service_name = Column(Text)
    service_info = Column(Text)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    observed_at = Column(Text, nullable=False)

    host = relationship("Host", back_populates="port_history")
    scan_job = relationship("ScanJob", back_populates="port_history")

    def __repr__(self) -> str:
        return f"<PortHistory(host_id={self.host_id}, port={self.port}, state={self.state})>"


class ChangeEvent(Base):  # type: ignore[misc]
    __tablename__ = "change_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Text, nullable=False, default="tcp")
    previous_state = Column(Text)
    current_state = Column(Text, nullable=False)
    previous_service = Column(Text)
    current_service = Column(Text)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    detected_at = Column(Text, nullable=False)
    notified = Column(Integer, nullable=False, default=0)

    host = relationship("Host", back_populates="change_events")
    scan_job = relationship("ScanJob", back_populates="change_events")

    def __repr__(self) -> str:
        return (
            f"<ChangeEvent(host_id={self.host_id}, port={self.port}, "
            f"{self.previous_state}->{self.current_state})>"
        )


class NotificationLog(Base):  # type: ignore[misc]
    __tablename__ = "notification_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel = Column(Text, nullable=False)
    change_event_ids = Column(Text, nullable=False)  # JSON array
    status = Column(Text, nullable=False)
    error_message = Column(Text)
    sent_at = Column(Text, nullable=False)

    def __repr__(self) -> str:
        return f"<NotificationLog(id={self.id}, channel={self.channel}, status={self.status})>"

"""
Modelos de datos para el sistema de licencias MIESC.
Usa SQLAlchemy para persistencia y Pydantic para validación.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, List
from dataclasses import dataclass, field

from sqlalchemy import Column, String, DateTime, Integer, Boolean, Enum as SQLEnum, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class LicenseStatus(str, Enum):
    """Estados posibles de una licencia."""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class PlanType(str, Enum):
    """Tipos de planes disponibles."""
    FREE = "FREE"
    STARTER = "STARTER"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class LicenseDB(Base):
    """Modelo SQLAlchemy para persistencia de licencias."""
    __tablename__ = "licenses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_key = Column(String(24), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    organization = Column(String(255), nullable=True)
    plan = Column(SQLEnum(PlanType), nullable=False, default=PlanType.FREE)
    status = Column(SQLEnum(LicenseStatus), nullable=False, default=LicenseStatus.ACTIVE)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # None = perpetua
    last_validated_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    # Relación con registros de uso
    usage_records = relationship("UsageRecordDB", back_populates="license", cascade="all, delete-orphan")


class UsageRecordDB(Base):
    """Modelo SQLAlchemy para registro de uso."""
    __tablename__ = "usage_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id = Column(String(36), ForeignKey("licenses.id"), nullable=False)
    month = Column(String(7), nullable=False)  # Formato: YYYY-MM
    audits_count = Column(Integer, nullable=False, default=0)
    last_audit_at = Column(DateTime, nullable=True)

    # Relación con licencia
    license = relationship("LicenseDB", back_populates="usage_records")


@dataclass
class License:
    """Modelo de dominio para licencia (en memoria)."""
    id: str
    license_key: str
    email: str
    plan: PlanType
    status: LicenseStatus
    created_at: datetime
    expires_at: Optional[datetime] = None
    organization: Optional[str] = None
    last_validated_at: Optional[datetime] = None
    notes: Optional[str] = None

    # Campos calculados de la configuración del plan
    max_audits_month: int = 5
    allowed_tools: List[str] = field(default_factory=list)
    ai_enabled: bool = False
    max_contract_size_kb: int = 50

    @property
    def is_active(self) -> bool:
        """Verifica si la licencia está activa."""
        if self.status != LicenseStatus.ACTIVE:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Verifica si la licencia ha expirado."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calcula días hasta la expiración."""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.days)

    def to_dict(self) -> dict:
        """Convierte a diccionario."""
        return {
            "id": self.id,
            "license_key": self.license_key,
            "email": self.email,
            "organization": self.organization,
            "plan": self.plan.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "max_audits_month": self.max_audits_month,
            "allowed_tools": self.allowed_tools,
            "ai_enabled": self.ai_enabled,
        }

    @classmethod
    def from_db(cls, db_license: LicenseDB, plan_config: dict) -> "License":
        """Crea instancia desde modelo de base de datos."""
        return cls(
            id=db_license.id,
            license_key=db_license.license_key,
            email=db_license.email,
            organization=db_license.organization,
            plan=db_license.plan,
            status=db_license.status,
            created_at=db_license.created_at,
            expires_at=db_license.expires_at,
            last_validated_at=db_license.last_validated_at,
            notes=db_license.notes,
            max_audits_month=plan_config.get("max_audits_month", 5),
            allowed_tools=plan_config.get("allowed_tools", []),
            ai_enabled=plan_config.get("ai_enabled", False),
            max_contract_size_kb=plan_config.get("max_contract_size_kb", 50),
        )


@dataclass
class UsageRecord:
    """Modelo de dominio para registro de uso."""
    id: str
    license_id: str
    month: str
    audits_count: int
    last_audit_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convierte a diccionario."""
        return {
            "id": self.id,
            "license_id": self.license_id,
            "month": self.month,
            "audits_count": self.audits_count,
            "last_audit_at": self.last_audit_at.isoformat() if self.last_audit_at else None,
        }

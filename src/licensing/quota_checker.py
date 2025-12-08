"""
Verificador de cuotas para MIESC.
Controla límites de uso según el plan de licencia.
"""

import logging
from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from pathlib import Path

from .models import Base, LicenseDB, UsageRecordDB, License, LicenseStatus
from .plans import get_plan_config, get_max_audits, get_max_contract_size, is_tool_allowed, is_ai_enabled

logger = logging.getLogger(__name__)


class QuotaChecker:
    """Verificador de cuotas y límites de uso."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Inicializa el verificador de cuotas.

        Args:
            database_url: URL de conexión a la base de datos
        """
        if database_url is None:
            data_dir = Path(__file__).parent.parent.parent / "data"
            data_dir.mkdir(exist_ok=True)
            database_url = f"sqlite:///{data_dir}/licenses.db"

        self.engine = create_engine(database_url, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def _get_session(self) -> Session:
        """Obtiene una sesión de base de datos."""
        return self.SessionLocal()

    def _get_current_month(self) -> str:
        """Obtiene el mes actual en formato YYYY-MM."""
        return datetime.utcnow().strftime("%Y-%m")

    def _get_or_create_usage_record(self, session: Session, license_id: str) -> UsageRecordDB:
        """
        Obtiene o crea un registro de uso para el mes actual.

        Args:
            session: Sesión de base de datos
            license_id: ID de la licencia

        Returns:
            Registro de uso
        """
        month = self._get_current_month()

        usage = session.query(UsageRecordDB).filter(
            UsageRecordDB.license_id == license_id,
            UsageRecordDB.month == month
        ).first()

        if not usage:
            usage = UsageRecordDB(
                id=str(uuid.uuid4()),
                license_id=license_id,
                month=month,
                audits_count=0,
            )
            session.add(usage)
            session.commit()
            session.refresh(usage)

        return usage

    def can_analyze(self, license: License) -> bool:
        """
        Verifica si una licencia puede ejecutar un análisis.

        Args:
            license: Licencia a verificar

        Returns:
            True si puede analizar
        """
        if not license.is_active:
            logger.warning(f"Licencia inactiva: {license.license_key}")
            return False

        # Plan Enterprise es ilimitado
        if license.plan.value == "ENTERPRISE":
            return True

        session = self._get_session()
        try:
            usage = self._get_or_create_usage_record(session, license.id)
            max_audits = get_max_audits(license.plan)

            if max_audits == -1:  # Ilimitado
                return True

            if usage.audits_count >= max_audits:
                logger.warning(
                    f"Límite de auditorías alcanzado: {license.license_key} "
                    f"({usage.audits_count}/{max_audits})"
                )
                return False

            return True

        finally:
            session.close()

    def can_use_tool(self, license: License, tool_name: str) -> bool:
        """
        Verifica si una licencia puede usar una herramienta específica.

        Args:
            license: Licencia a verificar
            tool_name: Nombre de la herramienta

        Returns:
            True si puede usar la herramienta
        """
        if not license.is_active:
            return False

        return is_tool_allowed(license.plan, tool_name)

    def can_use_ai(self, license: License) -> bool:
        """
        Verifica si una licencia puede usar funciones de IA.

        Args:
            license: Licencia a verificar

        Returns:
            True si puede usar IA
        """
        if not license.is_active:
            return False

        return is_ai_enabled(license.plan)

    def check_contract_size(self, license: License, size_kb: int) -> bool:
        """
        Verifica si el tamaño del contrato está dentro del límite.

        Args:
            license: Licencia a verificar
            size_kb: Tamaño del contrato en KB

        Returns:
            True si el tamaño es válido
        """
        if not license.is_active:
            return False

        max_size = get_max_contract_size(license.plan)

        if max_size == -1:  # Sin límite
            return True

        if size_kb > max_size:
            logger.warning(
                f"Contrato demasiado grande: {size_kb}KB > {max_size}KB "
                f"(licencia: {license.license_key})"
            )
            return False

        return True

    def record_audit(self, license: License) -> bool:
        """
        Registra una auditoría ejecutada.

        Args:
            license: Licencia utilizada

        Returns:
            True si se registró correctamente
        """
        session = self._get_session()
        try:
            usage = self._get_or_create_usage_record(session, license.id)
            usage.audits_count += 1
            usage.last_audit_at = datetime.utcnow()
            session.commit()

            logger.debug(
                f"Auditoría registrada: {license.license_key} "
                f"(total este mes: {usage.audits_count})"
            )
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error registrando auditoría: {e}")
            return False
        finally:
            session.close()

    def get_usage(self, license: License) -> dict:
        """
        Obtiene el uso actual de una licencia.

        Args:
            license: Licencia a consultar

        Returns:
            Diccionario con información de uso
        """
        session = self._get_session()
        try:
            usage = self._get_or_create_usage_record(session, license.id)
            max_audits = get_max_audits(license.plan)

            return {
                "month": usage.month,
                "audits_used": usage.audits_count,
                "audits_limit": max_audits if max_audits != -1 else "unlimited",
                "audits_remaining": (
                    max_audits - usage.audits_count if max_audits != -1 else "unlimited"
                ),
                "last_audit_at": usage.last_audit_at.isoformat() if usage.last_audit_at else None,
                "plan": license.plan.value,
                "allowed_tools": license.allowed_tools,
                "ai_enabled": license.ai_enabled,
                "max_contract_size_kb": license.max_contract_size_kb,
            }

        finally:
            session.close()

    def get_remaining_audits(self, license: License) -> int:
        """
        Obtiene el número de auditorías restantes.

        Args:
            license: Licencia a consultar

        Returns:
            Número de auditorías restantes (-1 si ilimitado)
        """
        max_audits = get_max_audits(license.plan)

        if max_audits == -1:
            return -1

        session = self._get_session()
        try:
            usage = self._get_or_create_usage_record(session, license.id)
            remaining = max_audits - usage.audits_count
            return max(0, remaining)
        finally:
            session.close()

    def filter_tools(self, license: License, requested_tools: list) -> list:
        """
        Filtra una lista de herramientas según el plan.

        Args:
            license: Licencia a verificar
            requested_tools: Lista de herramientas solicitadas

        Returns:
            Lista de herramientas permitidas
        """
        if not license.is_active:
            return []

        allowed = []
        for tool in requested_tools:
            if is_tool_allowed(license.plan, tool):
                allowed.append(tool)
            else:
                logger.debug(
                    f"Herramienta no permitida: {tool} "
                    f"(plan: {license.plan.value})"
                )

        return allowed

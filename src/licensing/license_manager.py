"""
Gestor de licencias para MIESC.
Maneja la validación, creación y gestión de licencias.
"""

import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from .models import Base, LicenseDB, UsageRecordDB, License, LicenseStatus, PlanType
from .plans import get_plan_config, PLANS
from .key_generator import generate_license_key, normalize_key

logger = logging.getLogger(__name__)


class LicenseManager:
    """Gestor principal de licencias."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Inicializa el gestor de licencias.

        Args:
            database_url: URL de conexión a la base de datos.
                         Por defecto usa SQLite en ./data/licenses.db
        """
        if database_url is None:
            # Default: SQLite local
            data_dir = Path(__file__).parent.parent.parent / "data"
            data_dir.mkdir(exist_ok=True)
            database_url = f"sqlite:///{data_dir}/licenses.db"

        self.engine = create_engine(database_url, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def _get_session(self) -> Session:
        """Obtiene una sesión de base de datos."""
        return self.SessionLocal()

    def create_license(
        self,
        email: str,
        plan: PlanType = PlanType.FREE,
        organization: Optional[str] = None,
        expires_days: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> License:
        """
        Crea una nueva licencia.

        Args:
            email: Email del propietario
            plan: Tipo de plan
            organization: Organización (opcional)
            expires_days: Días hasta expiración (None = perpetua)
            notes: Notas adicionales

        Returns:
            License: Licencia creada
        """
        session = self._get_session()
        try:
            license_key = generate_license_key()

            # Calcular fecha de expiración
            expires_at = None
            if expires_days is not None and expires_days > 0:
                expires_at = datetime.utcnow() + timedelta(days=expires_days)

            db_license = LicenseDB(
                id=str(uuid.uuid4()),
                license_key=license_key,
                email=email,
                organization=organization,
                plan=plan,
                status=LicenseStatus.ACTIVE,
                created_at=datetime.utcnow(),
                expires_at=expires_at,
                notes=notes,
            )

            session.add(db_license)
            session.commit()
            session.refresh(db_license)

            plan_config = get_plan_config(plan)
            license = License.from_db(db_license, plan_config)

            logger.info(f"Licencia creada: {license_key} para {email} (plan: {plan.value})")
            return license

        except Exception as e:
            session.rollback()
            logger.error(f"Error creando licencia: {e}")
            raise
        finally:
            session.close()

    def validate(self, license_key: str) -> Optional[License]:
        """
        Valida una clave de licencia.

        Args:
            license_key: Clave a validar

        Returns:
            License si es válida, None si no existe o es inválida
        """
        normalized_key = normalize_key(license_key)
        if not normalized_key:
            logger.warning(f"Formato de clave inválido: {license_key}")
            return None

        session = self._get_session()
        try:
            db_license = session.query(LicenseDB).filter(
                LicenseDB.license_key == normalized_key
            ).first()

            if not db_license:
                logger.warning(f"Licencia no encontrada: {normalized_key}")
                return None

            # Actualizar timestamp de validación
            db_license.last_validated_at = datetime.utcnow()

            # Verificar si ha expirado
            if db_license.expires_at and datetime.utcnow() > db_license.expires_at:
                if db_license.status == LicenseStatus.ACTIVE:
                    db_license.status = LicenseStatus.EXPIRED
                    logger.info(f"Licencia expirada automáticamente: {normalized_key}")

            session.commit()
            session.refresh(db_license)

            plan_config = get_plan_config(db_license.plan)
            license = License.from_db(db_license, plan_config)

            if license.is_active:
                logger.debug(f"Licencia válida: {normalized_key}")
                return license
            else:
                logger.warning(f"Licencia inactiva: {normalized_key} (status: {license.status})")
                return None

        except Exception as e:
            session.rollback()
            logger.error(f"Error validando licencia: {e}")
            return None
        finally:
            session.close()

    def get_license(self, license_key: str) -> Optional[License]:
        """
        Obtiene información de una licencia (sin validar estado).

        Args:
            license_key: Clave de licencia

        Returns:
            License o None
        """
        normalized_key = normalize_key(license_key)
        if not normalized_key:
            return None

        session = self._get_session()
        try:
            db_license = session.query(LicenseDB).filter(
                LicenseDB.license_key == normalized_key
            ).first()

            if not db_license:
                return None

            plan_config = get_plan_config(db_license.plan)
            return License.from_db(db_license, plan_config)

        finally:
            session.close()

    def list_licenses(
        self,
        status: Optional[LicenseStatus] = None,
        plan: Optional[PlanType] = None,
        email: Optional[str] = None,
    ) -> List[License]:
        """
        Lista licencias con filtros opcionales.

        Args:
            status: Filtrar por estado
            plan: Filtrar por plan
            email: Filtrar por email

        Returns:
            Lista de licencias
        """
        session = self._get_session()
        try:
            query = session.query(LicenseDB)

            if status:
                query = query.filter(LicenseDB.status == status)
            if plan:
                query = query.filter(LicenseDB.plan == plan)
            if email:
                query = query.filter(LicenseDB.email.ilike(f"%{email}%"))

            db_licenses = query.order_by(LicenseDB.created_at.desc()).all()

            licenses = []
            for db_license in db_licenses:
                plan_config = get_plan_config(db_license.plan)
                licenses.append(License.from_db(db_license, plan_config))

            return licenses

        finally:
            session.close()

    def update_license(
        self,
        license_key: str,
        status: Optional[LicenseStatus] = None,
        plan: Optional[PlanType] = None,
        expires_at: Optional[datetime] = None,
        notes: Optional[str] = None,
    ) -> Optional[License]:
        """
        Actualiza una licencia existente.

        Args:
            license_key: Clave de licencia
            status: Nuevo estado (opcional)
            plan: Nuevo plan (opcional)
            expires_at: Nueva fecha de expiración (opcional)
            notes: Nuevas notas (opcional)

        Returns:
            License actualizada o None si no existe
        """
        normalized_key = normalize_key(license_key)
        if not normalized_key:
            return None

        session = self._get_session()
        try:
            db_license = session.query(LicenseDB).filter(
                LicenseDB.license_key == normalized_key
            ).first()

            if not db_license:
                return None

            if status is not None:
                db_license.status = status
            if plan is not None:
                db_license.plan = plan
            if expires_at is not None:
                db_license.expires_at = expires_at
            if notes is not None:
                db_license.notes = notes

            session.commit()
            session.refresh(db_license)

            plan_config = get_plan_config(db_license.plan)
            license = License.from_db(db_license, plan_config)

            logger.info(f"Licencia actualizada: {normalized_key}")
            return license

        except Exception as e:
            session.rollback()
            logger.error(f"Error actualizando licencia: {e}")
            return None
        finally:
            session.close()

    def revoke_license(self, license_key: str) -> bool:
        """
        Revoca una licencia.

        Args:
            license_key: Clave de licencia

        Returns:
            True si se revocó correctamente
        """
        result = self.update_license(license_key, status=LicenseStatus.REVOKED)
        if result:
            logger.info(f"Licencia revocada: {license_key}")
            return True
        return False

    def suspend_license(self, license_key: str) -> bool:
        """
        Suspende una licencia temporalmente.

        Args:
            license_key: Clave de licencia

        Returns:
            True si se suspendió correctamente
        """
        result = self.update_license(license_key, status=LicenseStatus.SUSPENDED)
        if result:
            logger.info(f"Licencia suspendida: {license_key}")
            return True
        return False

    def reactivate_license(self, license_key: str) -> bool:
        """
        Reactiva una licencia suspendida.

        Args:
            license_key: Clave de licencia

        Returns:
            True si se reactivó correctamente
        """
        result = self.update_license(license_key, status=LicenseStatus.ACTIVE)
        if result:
            logger.info(f"Licencia reactivada: {license_key}")
            return True
        return False

    def get_stats(self) -> dict:
        """
        Obtiene estadísticas de licencias.

        Returns:
            Diccionario con estadísticas
        """
        session = self._get_session()
        try:
            total = session.query(LicenseDB).count()
            active = session.query(LicenseDB).filter(
                LicenseDB.status == LicenseStatus.ACTIVE
            ).count()
            expired = session.query(LicenseDB).filter(
                LicenseDB.status == LicenseStatus.EXPIRED
            ).count()
            suspended = session.query(LicenseDB).filter(
                LicenseDB.status == LicenseStatus.SUSPENDED
            ).count()
            revoked = session.query(LicenseDB).filter(
                LicenseDB.status == LicenseStatus.REVOKED
            ).count()

            # Por plan
            by_plan = {}
            for plan_type in PlanType:
                count = session.query(LicenseDB).filter(
                    LicenseDB.plan == plan_type
                ).count()
                by_plan[plan_type.value] = count

            return {
                "total": total,
                "active": active,
                "expired": expired,
                "suspended": suspended,
                "revoked": revoked,
                "by_plan": by_plan,
            }

        finally:
            session.close()

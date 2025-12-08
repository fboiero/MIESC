"""
Generador de claves de licencia para MIESC.
Formato: MIESC-XXXX-XXXX-XXXX-XXXX
"""

import secrets
import hashlib
import re
from typing import Optional


def generate_license_key() -> str:
    """
    Genera una clave de licencia única.
    Formato: MIESC-XXXX-XXXX-XXXX-XXXX (donde X es hexadecimal mayúscula)

    Returns:
        str: Clave de licencia generada
    """
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return f"MIESC-{'-'.join(parts)}"


def validate_key_format(key: str) -> bool:
    """
    Valida el formato de una clave de licencia.

    Args:
        key: Clave a validar

    Returns:
        bool: True si el formato es válido
    """
    pattern = r'^MIESC-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$'
    return bool(re.match(pattern, key.upper()))


def normalize_key(key: str) -> Optional[str]:
    """
    Normaliza una clave de licencia (mayúsculas, sin espacios).

    Args:
        key: Clave a normalizar

    Returns:
        str o None: Clave normalizada o None si es inválida
    """
    if not key:
        return None

    # Remover espacios y convertir a mayúsculas
    normalized = key.strip().upper().replace(" ", "")

    # Agregar prefijo si no lo tiene
    if not normalized.startswith("MIESC-"):
        # Intentar agregar guiones si faltan
        if len(normalized) == 16 and normalized.isalnum():
            normalized = f"MIESC-{normalized[:4]}-{normalized[4:8]}-{normalized[8:12]}-{normalized[12:16]}"

    # Validar formato
    if validate_key_format(normalized):
        return normalized

    return None


def generate_checksum(key: str) -> str:
    """
    Genera un checksum para una clave (para verificación adicional).

    Args:
        key: Clave de licencia

    Returns:
        str: Checksum de 8 caracteres
    """
    return hashlib.sha256(key.encode()).hexdigest()[:8].upper()


def generate_key_with_checksum() -> tuple[str, str]:
    """
    Genera una clave con su checksum.

    Returns:
        tuple: (clave, checksum)
    """
    key = generate_license_key()
    checksum = generate_checksum(key)
    return key, checksum

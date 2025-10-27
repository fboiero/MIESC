# 🧪 Test Contracts - MIESC Demo Collection

Colección de contratos inteligentes vulnerables para pruebas y demostraciones de MIESC.

---

## 📁 Contenido

### Contratos Propios

#### `VulnerableBank.sol`
Contrato bancario con múltiples vulnerabilidades intencionales para demostración educativa.

**Versión:** Solidity ^0.8.0
**LOC:** 108 líneas
**Vulnerabilidades:** 6 intencionales, 17 total detectadas

**Vulnerabilidades Incluidas:**
1. ✓ Reentrancy Attack
2. ✓ Controlled Delegatecall
3. ✓ Missing Access Control
4. ✓ tx.origin Usage
5. ✓ Timestamp Dependency
6. ✓ Weak PRNG

**Uso:**
```bash
# Análisis con Slither
slither test_contracts/VulnerableBank.sol

# Análisis con MIESC (futuro)
miesc analyze test_contracts/VulnerableBank.sol
```

**Resultados:** Ver `DEMO_RESULTS.md`

---

### Contratos Externos

#### `not-so-smart-contracts/`
Repositorio clonado de Trail of Bits con contratos vulnerables históricos.

**Fuente:** https://github.com/crytic/not-so-smart-contracts
**Mantenedor:** Trail of Bits
**Propósito:** Ejemplos educativos de vulnerabilidades reales

**Contenido:**
- `reentrancy/` - Ejemplos de ataques de reentrada (The DAO, SpankChain)
- `integer_overflow/` - Ejemplos de overflow de enteros
- `bad_randomness/` - Uso incorrecto de aleatoriedad
- `wrong_constructor_name/` - Errores en constructores
- `honeypots/` - Contratos honeypot

**Nota:** Estos contratos usan versiones antiguas de Solidity (0.4.x) y pueden requerir configuración especial de compilador.

---

## 🎯 Resultados de Pruebas

### Última Ejecución: 27 de Octubre, 2025

**Herramienta:** Slither v0.9.6
**Contrato:** VulnerableBank.sol
**Detectores:** 88
**Vulnerabilidades:** 17 encontradas

| Severidad | Cantidad |
|-----------|----------|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 5 |
| INFO | 6 |

**Cobertura:** 100% de vulnerabilidades intencionales detectadas

Ver detalles completos en: `DEMO_RESULTS.md`

---

## 🚀 Uso para Demos y Presentaciones

### Demo Rápido (5 minutos)
```bash
# 1. Mostrar el contrato vulnerable
cat test_contracts/VulnerableBank.sol

# 2. Ejecutar Slither
slither test_contracts/VulnerableBank.sol

# 3. Mostrar resultados
cat test_contracts/DEMO_RESULTS.md
```

### Demo Completo con MIESC (25 minutos)
```bash
# Usar el script de defensa de tesis
python3 demo/thesis_defense_demo.py

# Seleccionar opción 3: Demostración Práctica
# O ejecutar directamente la demo de orquestación
python3 demo/orchestration_demo.py test_contracts/VulnerableBank.sol
```

---

## 📚 Propósito Educativo

Estos contratos son **SOLO PARA FINES EDUCATIVOS** y demostraciones.

**NO USAR EN PRODUCCIÓN**

Cada vulnerabilidad está:
- ✓ Claramente comentada en el código
- ✓ Documentada en DEMO_RESULTS.md
- ✓ Acompañada de versión segura cuando aplica

---

## 🔧 Requisitos

**Para Análisis Estático:**
- Solidity Compiler (solc) v0.8.0+
- Slither v0.9.6+
- Python 3.9+

**Instalación:**
```bash
# Instalar Slither
pip install slither-analyzer

# Verificar instalación
slither --version
```

---

## 📖 Referencias

### Documentación de Vulnerabilidades

- **SWC Registry:** https://swcregistry.io/
- **Slither Detectors:** https://github.com/crytic/slither/wiki/Detector-Documentation
- **Consensys Best Practices:** https://consensys.github.io/smart-contract-best-practices/

### Recursos de Trail of Bits

- **Not So Smart Contracts:** https://github.com/crytic/not-so-smart-contracts
- **Building Secure Contracts:** https://github.com/crytic/building-secure-contracts
- **Trail of Bits Blog:** https://blog.trailofbits.com/

---

## 🎓 Uso Académico

Estos contratos se utilizan para:

1. **Defensa de Tesis** - Demostración de capacidades de MIESC
2. **Presentaciones Académicas** - Conferencias y seminarios
3. **Enseñanza** - Cursos de seguridad en blockchain
4. **Benchmarking** - Comparación de herramientas de análisis

**Tesis:** "Marco Integrado de Evaluación de Seguridad en Smart Contracts"
**Institución:** UNDEF - IUA Córdoba
**Programa:** Maestría en Ciberdefensa
**Autor:** Fernando Boiero

---

## 🔄 Actualización de Contratos

Para agregar nuevos contratos de prueba:

1. Crear contrato en esta carpeta
2. Documentar vulnerabilidades en comentarios
3. Ejecutar análisis con herramientas
4. Actualizar DEMO_RESULTS.md
5. Agregar referencia en este README

---

## ⚠️ Advertencias

1. **NUNCA deployar estos contratos en mainnet**
2. **NO usar para manejar fondos reales**
3. **Solo para entornos de prueba y educación**
4. **Las vulnerabilidades son intencionales**

---

**Última actualización:** 27 de Octubre, 2025
**Versión MIESC:** v3.3.0
**Mantenedor:** Fernando Boiero (fboiero@frvm.utn.edu.ar)

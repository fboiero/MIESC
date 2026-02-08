# Política de Privacidad

**[English Version](PRIVACY.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**

*Última Actualización: Diciembre 2024*

---

## Descripción General

MIESC está comprometido con la protección de la privacidad de los usuarios. Este documento describe nuestras prácticas de manejo de datos y compromisos de privacidad.

**Principio Clave**: MIESC procesa todos los datos localmente en tu máquina. Tu código y resultados de análisis nunca salen de tu sistema a menos que elijas compartirlos explícitamente.

---

## Recopilación de Datos

### Lo Que NO Recopilamos

| Tipo de Dato | ¿Recopilado? | Notas |
|--------------|--------------|-------|
| Código fuente | No | Procesado solo localmente |
| Resultados de análisis | No | Almacenados solo localmente |
| Información personal | No | No se requieren cuentas de usuario |
| Telemetría de uso | No | Sin analytics por defecto |
| Direcciones IP | No | Sin solicitudes de red a servidores MIESC |
| Cookies | No | Sin seguimiento web |

### Lo Que PODEMOS Procesar Localmente

| Tipo de Dato | Propósito | Almacenamiento |
|--------------|-----------|----------------|
| Archivos fuente Solidity | Análisis de seguridad | Temporal, eliminado después del análisis |
| Artefactos de compilación | Ejecución de herramientas | Caché temporal, controlado por usuario |
| Reportes de análisis | Entregable del usuario | Solo sistema de archivos local |
| Archivos de configuración | Preferencias del usuario | Solo sistema de archivos local |

---

## Arquitectura de Procesamiento Local

```
┌─────────────────────────────────────────────────────────────┐
│                    TU MÁQUINA LOCAL                          │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Código Fuente│───▶│    MIESC     │───▶│  Reportes    │  │
│  │   (Entrada)  │    │   (Local)    │    │   (Salida)   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                             │                               │
│                             ▼                               │
│                    ┌──────────────┐                         │
│                    │  LLM Local   │                         │
│                    │  (Ollama)    │                         │
│                    └──────────────┘                         │
│                                                              │
│          ══════════════════════════════════════             │
│          ║  NINGÚN DATO SALE DE ESTE LÍMITE  ║              │
│          ══════════════════════════════════════             │
└─────────────────────────────────────────────────────────────┘
```

---

## Componentes de IA/ML

### LLM Local (Por Defecto)

MIESC usa **Ollama** para análisis asistido por IA por defecto:

- Se ejecuta completamente en tu máquina local
- Sin llamadas API a servicios externos
- Sin transmisión de datos a proveedores de nube
- Los modelos se descargan una vez, se ejecutan offline

### IA en la Nube Opcional

Si eliges habilitar funciones de IA en la nube (GPT-4):

- **Solo opt-in**: Requiere configuración explícita
- **Tu responsabilidad**: Debes revisar la política de privacidad del proveedor
- **Transmisión de datos**: Fragmentos de código fuente pueden enviarse a la API
- **Recomendación**: Usa modelos locales para código sensible

---

## Herramientas de Terceros

MIESC orquesta herramientas de seguridad de terceros. Cada herramienta tiene sus propias características de privacidad:

| Herramienta | Acceso a Red | Datos Enviados Externamente |
|-------------|--------------|----------------------------|
| Slither | Ninguno | Ninguno |
| Mythril | Ninguno | Ninguno |
| Echidna | Ninguno | Ninguno |
| Foundry | Opcional (dependencias) | Solo checksums de paquetes |
| Halmos | Ninguno | Ninguno |
| Certora | Sí (si se usa) | Código enviado a nube Certora |
| SMTChecker | Ninguno | Ninguno |

**Nota**: El servicio de verificación en la nube de Certora requiere enviar código a sus servidores. Esto es opcional y está claramente documentado cuando se habilita.

---

## Retención de Datos

### Limpieza Automática

| Tipo de Dato | Retención | Método de Limpieza |
|--------------|-----------|-------------------|
| Archivos temporales | Solo sesión | Eliminados al salir |
| Caché de compilación | Controlado por usuario | Manual o `make clean` |
| Reportes de análisis | Permanente | El usuario gestiona |
| Logs | 7 días por defecto | Configurable |

### Control del Usuario

Los usuarios tienen control total sobre todos los datos almacenados:

```bash
# Limpiar todos los datos temporales
make clean

# Limpiar caché de análisis
rm -rf .miesc_cache/

# Limpiar logs
rm -rf logs/
```

---

## Cumplimiento Legal

### GDPR (Reglamento General de Protección de Datos de la UE)

| Requisito | Cumplimiento MIESC |
|-----------|-------------------|
| Base legal | No aplica (sin procesamiento de datos personales) |
| Minimización de datos | Solo procesa archivos explícitamente proporcionados |
| Limitación de propósito | Solo análisis de seguridad |
| Limitación de almacenamiento | Retención controlada por usuario |
| Derecho de supresión | El usuario elimina archivos locales |
| Portabilidad de datos | Todas las exportaciones en formatos abiertos |

### CCPA (Ley de Privacidad del Consumidor de California)

| Requisito | Cumplimiento MIESC |
|-----------|-------------------|
| Derecho a saber | Esta política documenta todo el manejo de datos |
| Derecho a eliminar | El usuario controla todos los datos locales |
| Derecho a opt-out | Sin venta de datos (sin recopilación de datos) |
| No discriminación | Herramienta gratuita, sin diferenciación de usuarios |

### Ley de Protección de Datos de Argentina (Ley 25.326)

| Requisito | Cumplimiento MIESC |
|-----------|-------------------|
| Especificación de propósito | Solo análisis de seguridad |
| Calidad de datos | Sin datos personales almacenados |
| Medidas de seguridad | Procesamiento local, sin transmisión |
| Derechos del usuario | Control total del usuario sobre los datos |

---

## Medidas de Seguridad

### Protección de Datos

| Medida | Implementación |
|--------|----------------|
| Cifrado en reposo | Cifrado del sistema de archivos del usuario (nivel OS) |
| Cifrado en tránsito | N/A (sin transmisión de datos) |
| Control de acceso | Permisos del sistema de archivos del usuario |
| Registro de auditoría | Opcional, solo local |

### Manejo de Vulnerabilidades

- Issues de seguridad: fboiero@frvm.utn.edu.ar
- Tiempo de respuesta: <48 horas
- Política de divulgación: Divulgación coordinada

---

## Privacidad de Menores

MIESC es una herramienta de desarrollo destinada al uso profesional. No:
- Recopilamos conscientemente datos de menores de 13 años
- Hacemos marketing para niños
- Proporcionamos características diseñadas para menores

---

## Transferencias Internacionales de Datos

**No ocurren transferencias internacionales de datos** porque:
- Todo el procesamiento es local
- Sin datos enviados a servidores MIESC
- Sin servicios en la nube requeridos por defecto

Si habilitas funciones opcionales de IA en la nube, las transferencias se rigen por las políticas del proveedor.

---

## Cambios a Esta Política

Actualizaremos esta política según sea necesario. Los cambios serán:
- Documentados en commits del repositorio
- Anotados en notas de lanzamiento
- Efectivos inmediatamente tras la publicación

---

## Contacto

**Preguntas de Privacidad**: fboiero@frvm.utn.edu.ar

**Repositorio del Proyecto**: https://github.com/fboiero/MIESC

---

## Resumen

| Pregunta | Respuesta |
|----------|-----------|
| ¿MIESC recopila mis datos? | No |
| ¿MIESC envía datos externamente? | No (por defecto) |
| ¿Dónde se procesa mi código? | Solo en tu máquina local |
| ¿Quién puede acceder a mis resultados de análisis? | Solo tú |
| ¿Necesito una cuenta? | No |
| ¿Hay telemetría? | No |

**Tu código permanece en tu máquina. Siempre.**

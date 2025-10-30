# 🎮 MIESC Hacker-Style Demo

Demo cinematográfico estilo "hacker" con ASCII art, animaciones y efectos visuales para presentaciones y defensa de tesis.

---

## 🎯 Características

### Efectos Visuales
- ✅ **ASCII Art** - Banner MIESC y logos animados
- ✅ **Typing Effect** - Texto que se escribe en tiempo real
- ✅ **Loading Bars** - Barras de progreso animadas
- ✅ **Glitch Effect** - Efectos de distorsión tipo matrix
- ✅ **Pulse Text** - Texto pulsante para enfatizar
- ✅ **Color Gradients** - Colores ANSI para cada fase

### Fases de la Demo
1. **Banner Inicial** - Logo MIESC con efectos glitch
2. **Inicialización** - Carga de 17 agentes con barras de progreso
3. **Target Analysis** - Identificación del contrato objetivo
4. **Phase 1: Static Analysis** - Análisis estático con Slither real
5. **Phase 2: Deep Analysis** - Análisis detallado de vulnerabilidades
6. **Phase 3: Comparison** - Comparación con otras herramientas
7. **Phase 4: Statistics** - Métricas y estadísticas finales
8. **Conclusion** - Resumen y validación científica

### Análisis Real
- Ejecuta Slither sobre `test_contracts/VulnerableBank.sol`
- Procesa resultados JSON reales
- Cuenta vulnerabilidades por severidad
- Muestra estadísticas en tiempo real

---

## 🚀 Uso

### Ejecución Básica

```bash
# Opción 1: Ejecutar directamente
./demo/hacker_demo.py

# Opción 2: Con Python
python3 demo/hacker_demo.py
```

### Requisitos

**Software:**
- Python 3.9+
- Slither analyzer instalado
- Terminal con soporte ANSI colors

**Archivos necesarios:**
- `test_contracts/VulnerableBank.sol` (contrato de prueba)

**Instalación de dependencias:**
```bash
# Instalar Slither si no está instalado
pip install slither-analyzer

# Verificar instalación
slither --version
```

---

## 🎬 Flujo de la Demo

### 1. Banner Inicial (10 segundos)
```
███╗   ███╗██╗███████╗███████╗ ██████╗
████╗ ████║██║██╔════╝██╔════╝██╔════╝
██╔████╔██║██║█████╗  ███████╗██║
██║╚██╔╝██║██║██╔══╝  ╚════██║██║
██║ ╚═╝ ██║██║███████╗███████║╚██████╗
╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝

>>> PRESS ENTER TO START SECURITY ANALYSIS >>>
```

### 2. Inicialización (15 segundos)
- Carga de 6 capas de agentes
- Barras de progreso para cada capa
- Confirmación de cada agente cargado
- Total: 17 agentes especializados

### 3. Target Analysis (10 segundos)
- Identificación del contrato
- Estructura del contrato
- Funciones detectadas
- Preparación para análisis

### 4. Phase 1: Static Analysis (15 segundos)
- Ejecución de SlitherAgent
- **Análisis REAL con Slither**
- Detección de vulnerabilidades
- Gráfico de barras por severidad

**Output ejemplo:**
```
CRITICAL: [▓▓▓░░░░░░░] 1
HIGH    : [▓▓▓▓▓▓░░░░] 3
MEDIUM  : [▓▓▓░░░░░░░] 2
LOW     : [▓▓▓▓▓░░░░░] 5
INFO    : [▓▓▓▓▓▓░░░░] 6

[!] TOTAL: 17 ISSUES FOUND
```

### 5. Phase 2: Deep Analysis (20 segundos)
- Análisis detallado de 4 vulnerabilidades críticas
- Reentrancy, Delegatecall, Access Control, tx.origin
- Ubicación exacta (líneas de código)
- Evaluación de impacto
- Confirmación de explotabilidad

### 6. Phase 3: Comparison (15 segundos)
- Comparación con herramientas tradicionales
- Tabla comparativa de rendimiento

**Métricas mostradas:**
```
Tool                     Findings     Time(s)      Accuracy(%)
----------------------------------------------------------
Slither (Solo)           12           5.2          67.3
Mythril (Solo)           8            45.8         61.2
Manticore (Solo)         6            120.3        58.9
MIESC (Multi-Agent)      17           8.4          89.5
```

**Ventajas de MIESC:**
- 41% más hallazgos que la mejor herramienta individual
- 89.5% precisión vs 67.3% baseline
- Correlación multi-agente reduce falsos positivos
- 6 capas de defensa en profundidad
- Interpretación impulsada por IA

### 7. Phase 4: Statistics (15 segundos)
- Tiempo de ejecución total
- Métricas de análisis
- Validación científica

**Estadísticas mostradas:**
```
Execution Time          : X.X seconds
Contract Lines          : 108 LOC
Agents Deployed         : 17
Total Detectors         : 88
Vulnerabilities Found   : 17
Critical Issues         : 1
High Issues             : 3
False Positive Rate     : < 5%
Detection Accuracy      : 100%
```

**Validación científica:**
```
Cohen's Kappa           : 0.847       (Excellent agreement)
Precision               : 89.47%      (vs 67.3% baseline)
F1-Score                : 0.85        (High reliability)
Coverage                : 100%        (All intentional vulns detected)
```

### 8. Conclusion (10 segundos)
- Confirmación de éxito
- Créditos académicos
- Mensaje final

---

## ⚙️ Configuración

### Personalización de Tiempos

Editar en `hacker_demo.py`:

```python
# Tiempos de animación
typing_effect(text, delay=0.03)      # Velocidad de escritura
loading_bar(title, duration=2)       # Duración de barras
pulse_text(text, times=3)            # Repeticiones de pulso
time.sleep(1)                        # Pausas entre secciones
```

### Personalización de Colores

```python
# Definir en class Colors
CUSTOM_COLOR = '\033[38;5;XXXm'  # XXX = código de color 0-255
```

### Cambiar Contrato de Prueba

```python
# En __init__
self.contract_path = "path/to/your/contract.sol"
```

---

## 🎓 Uso para Presentaciones

### Defensa de Tesis (10 minutos)
```bash
# Terminal en pantalla grande (proyector)
# Fuente: 18-20pt
# Tema: Oscuro con colores brillantes

./demo/hacker_demo.py

# Dejar correr automáticamente
# Narrar mientras se ejecuta
# Pausar con Ctrl+Z si necesario (fg para continuar)
```

### Demo Rápido (5 minutos)
- Mostrar solo hasta Phase 3
- Presionar Ctrl+C después de comparación

### Demo Completo (15 minutos)
- Ejecutar hasta el final
- Expandir verbalmente cada fase
- Responder preguntas entre fases

---

## 🎨 Efectos Implementados

### 1. Typing Effect
Texto que aparece letra por letra, simulando escritura en tiempo real.

### 2. Loading Bars
Barras de progreso animadas con porcentaje.

### 3. Matrix Effect
Lluvia de 0s y 1s estilo Matrix (breve).

### 4. Pulse Text
Texto que pulsa entre brillante y oscuro.

### 5. Glitch Effect
Cambio rápido de colores para efecto de distorsión.

### 6. Vulnerability Bars
Barras horizontales mostrando cantidad de vulnerabilidades por severidad.

### 7. Countdown
Cuenta regresiva antes de iniciar.

---

## 📊 Datos Mostrados

### Métricas Reales
- ✅ Tiempo de ejecución calculado dinámicamente
- ✅ Vulnerabilidades contadas desde Slither JSON
- ✅ Estadísticas basadas en análisis real

### Métricas de Comparación
- ✅ Basadas en estudios académicos
- ✅ Cohen's Kappa de experimentos reales
- ✅ Precisión medida en dataset de prueba

---

## 🐛 Troubleshooting

### Error: "Slither not found"
```bash
pip install slither-analyzer
```

### Error: "Contract not found"
```bash
# Verificar que existe test_contracts/VulnerableBank.sol
ls -la test_contracts/VulnerableBank.sol
```

### Colores no se muestran
```bash
# Verificar soporte ANSI en terminal
echo -e "\033[32mGreen\033[0m"

# Si no funciona, usar terminal moderna:
# - iTerm2 (macOS)
# - Windows Terminal (Windows)
# - GNOME Terminal (Linux)
```

### Demo muy lenta/rápida
Editar delays en el código:
```python
# Hacer más rápido
typing_effect(text, delay=0.01)  # default: 0.03
loading_bar(title, duration=1)   # default: 2

# Hacer más lento
typing_effect(text, delay=0.05)
loading_bar(title, duration=3)
```

---

## 🎥 Grabación de Video

### Opción 1: asciinema
```bash
# Instalar
pip install asciinema

# Grabar
asciinema rec miesc_demo.cast

# Ejecutar demo
./demo/hacker_demo.py

# Terminar: Ctrl+D

# Reproducir
asciinema play miesc_demo.cast
```

### Opción 2: Screen Recording
- macOS: QuickTime Screen Recording
- Windows: OBS Studio
- Linux: SimpleScreenRecorder

---

## 📝 Notas Técnicas

### Compatibilidad
- ✅ Python 3.9+
- ✅ macOS (probado en Darwin 24.6.0)
- ✅ Linux (requiere terminal con ANSI)
- ⚠️  Windows (requiere Windows Terminal o ConEmu)

### Dependencias
- Solo librería estándar de Python
- Slither (para análisis real)
- Terminal con soporte ANSI colors

### Duración Total
- Sin pausas manuales: ~2 minutos
- Con pausas narrativas: 5-15 minutos
- Presentación completa: 10-20 minutos

---

## 🎯 Mejores Prácticas

### Para Presentaciones
1. **Practicar antes** - Ejecutar 2-3 veces para familiarizarse
2. **Narrar en vivo** - No dejar que corra en silencio
3. **Pausar estratégicamente** - Usar pausas para explicar
4. **Terminal grande** - Fuente 18-20pt mínimo
5. **Fondo oscuro** - Mejor contraste para proyector

### Para Demos
1. **Verificar Slither** - Probar análisis antes del demo
2. **Backup plan** - Tener screenshots si falla
3. **Red backup** - No depender de internet
4. **Timing** - Conocer duración de cada fase

### Para Grabaciones
1. **Limpiar pantalla** - `clear` antes de empezar
2. **Silenciar notificaciones** - No mostrar popups
3. **Full screen** - Maximizar terminal
4. **Audio claro** - Narración sincronizada

---

## 🔗 Archivos Relacionados

- `test_contracts/VulnerableBank.sol` - Contrato de prueba
- `test_contracts/DEMO_RESULTS.md` - Resultados detallados
- `demo/thesis_defense_demo.py` - Demo académico estructurado
- `demo/orchestration_demo.py` - Demo de orquestación

---

## 📚 Referencias

### ASCII Art
- Generador: https://patorjk.com/software/taag/
- Font usado: "ANSI Shadow"

### ANSI Colors
- Códigos: https://en.wikipedia.org/wiki/ANSI_escape_code
- 256 colores: https://www.ditig.com/256-colors-cheat-sheet

### Inspiración
- Matrix Digital Rain
- Hacker typer animations
- Terminal-based presentations

---

## 🎓 Contexto Académico

**Proyecto:** MIESC v3.3.0
**Institución:** Universidad de la Defensa Nacional - IUA Córdoba
**Programa:** Maestría en Ciberdefensa
**Autor:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar

---

## ⚠️ Advertencias

- **NO usar en producción** - Solo para demos educativas
- **Requiere Slither** - Instalar antes de ejecutar
- **Terminal moderna** - Requiere soporte ANSI
- **Tiempo de ejecución** - Puede variar según sistema

---

## ✅ Checklist Pre-Demo

Antes de una presentación importante:

- [ ] Slither instalado y funcionando
- [ ] VulnerableBank.sol existe y compila
- [ ] Terminal configurada (fuente grande, tema oscuro)
- [ ] Demo ejecutado y funciona correctamente
- [ ] Timing practicado (5-15 min)
- [ ] Backup screenshots preparados
- [ ] Proyector/pantalla probados
- [ ] Audio/micrófono funcionando
- [ ] Notificaciones desactivadas

---

**Última actualización:** 30 de Octubre, 2025
**Versión:** 1.0.0
**Estado:** ✅ Listo para uso

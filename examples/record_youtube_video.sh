#!/bin/bash
# =============================================================================
# MIESC YouTube Video Recorder
# Graba, convierte y prepara el video para YouTube
#
# Requisitos:
#   - asciinema: brew install asciinema
#   - agg: cargo install agg
#   - ffmpeg: brew install ffmpeg
#
# Uso: ./demo/record_youtube_video.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo/recordings"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "=========================================="
echo "  MIESC YouTube Video Recorder"
echo "=========================================="
echo -e "${NC}"

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

# Verificar dependencias
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 no está instalado${NC}"
        echo "Instalar con: $2"
        exit 1
    fi
}

echo -e "${YELLOW}Verificando dependencias...${NC}"
check_dependency "asciinema" "brew install asciinema"
check_dependency "ffmpeg" "brew install ffmpeg"

# agg es opcional
if command -v agg &> /dev/null; then
    HAS_AGG=true
    echo -e "${GREEN}agg disponible${NC}"
else
    HAS_AGG=false
    echo -e "${YELLOW}agg no disponible (video será más básico)${NC}"
    echo "Para mejor calidad: cargo install agg"
fi

echo ""

# Configuración de grabación
CAST_FILE="$OUTPUT_DIR/miesc_demo_$TIMESTAMP.cast"
GIF_FILE="$OUTPUT_DIR/miesc_demo_$TIMESTAMP.gif"
MP4_FILE="$OUTPUT_DIR/miesc_demo_$TIMESTAMP.mp4"
FINAL_FILE="$OUTPUT_DIR/miesc_youtube_$TIMESTAMP.mp4"

# Dimensiones del terminal para grabación
COLS=120
ROWS=35

echo -e "${CYAN}Configuración de grabación:${NC}"
echo "  Terminal: ${COLS}x${ROWS}"
echo "  Archivo: $CAST_FILE"
echo ""

echo -e "${GREEN}Iniciando grabación en 3 segundos...${NC}"
echo -e "${YELLOW}La demo v2 dura aproximadamente 2 minutos${NC}"
echo -e "${YELLOW}Tip: Maximiza el terminal para mejor calidad${NC}"
sleep 3

# Grabar con asciinema
echo -e "${CYAN}Grabando...${NC}"
asciinema rec "$CAST_FILE" \
    --overwrite \
    --cols "$COLS" \
    --rows "$ROWS" \
    -c "bash $SCRIPT_DIR/youtube_demo_v2.sh"

echo ""
echo -e "${GREEN}Grabación completada!${NC}"
echo ""

# Convertir a GIF/MP4
echo -e "${CYAN}Convirtiendo a video...${NC}"

if [ "$HAS_AGG" = true ]; then
    # Usar agg para alta calidad
    echo "  Generando GIF con agg..."
    agg "$CAST_FILE" "$GIF_FILE" \
        --cols "$COLS" \
        --rows "$ROWS" \
        --font-size 14 \
        --theme monokai \
        --speed 1.0

    echo "  Convirtiendo a MP4..."
    ffmpeg -y -i "$GIF_FILE" \
        -movflags faststart \
        -pix_fmt yuv420p \
        -vf "fps=30,scale=1920:-2" \
        "$MP4_FILE" 2>/dev/null
else
    # Usar asciinema-player y captura de pantalla
    echo "  Generando video básico..."
    # Fallback: usar svg2png si está disponible
    echo -e "${YELLOW}  Para mejor calidad, instala agg: cargo install agg${NC}"
fi

# Verificar que el video existe
if [ -f "$MP4_FILE" ]; then
    # Obtener duración
    DURATION=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$MP4_FILE" 2>/dev/null || echo "unknown")

    echo ""
    echo -e "${GREEN}=========================================="
    echo "  Video creado exitosamente!"
    echo "==========================================${NC}"
    echo ""
    echo -e "${CYAN}Archivos generados:${NC}"
    echo "  Cast:  $CAST_FILE"
    [ -f "$GIF_FILE" ] && echo "  GIF:   $GIF_FILE"
    echo "  MP4:   $MP4_FILE"
    echo ""
    echo -e "${CYAN}Duración:${NC} ${DURATION}s"
    echo ""

    # Generar subtítulos
    echo -e "${YELLOW}Generando archivo de subtítulos...${NC}"
    cat > "$OUTPUT_DIR/subtitles_$TIMESTAMP.srt" << 'EOF'
1
00:00:00,000 --> 00:00:06,000
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts
Framework de Seguridad Defense-in-Depth

2
00:00:06,000 --> 00:00:12,000
31 herramientas de seguridad integradas en 9 capas de defensa

3
00:00:30,000 --> 00:00:40,000
Instalacion: pip install miesc

4
00:00:50,000 --> 00:01:00,000
miesc doctor - Verificar herramientas disponibles

5
00:01:30,000 --> 00:01:45,000
Escaneo rapido de vulnerabilidades

6
00:02:00,000 --> 00:02:15,000
Detectando reentrancy y access control issues

7
00:02:30,000 --> 00:03:00,000
Auditoria completa de 9 capas de defensa

8
00:04:00,000 --> 00:04:30,000
Generacion de reportes profesionales

9
00:05:00,000 --> 00:05:20,000
Tracking de postura de seguridad

10
00:05:30,000 --> 00:06:00,000
Integraciones: Foundry, Hardhat, VS Code, Pre-commit

11
00:06:30,000 --> 00:07:00,000
pip install miesc | github.com/fboiero/MIESC

EOF
    echo "  Subtítulos: $OUTPUT_DIR/subtitles_$TIMESTAMP.srt"

    # Instrucciones para agregar voz
    echo ""
    echo -e "${YELLOW}Próximos pasos:${NC}"
    echo ""
    echo "1. Agregar narración de voz:"
    echo "   - Graba el audio siguiendo YOUTUBE_VIDEO_SCRIPT.md"
    echo "   - Combina con: ffmpeg -i $MP4_FILE -i audio.mp3 -c:v copy -c:a aac final.mp4"
    echo ""
    echo "2. Agregar subtítulos:"
    echo "   - ffmpeg -i $MP4_FILE -vf subtitles=$OUTPUT_DIR/subtitles_$TIMESTAMP.srt output.mp4"
    echo ""
    echo "3. Subir a YouTube con los metadatos de YOUTUBE_VIDEO_SCRIPT.md"
    echo ""

else
    echo -e "${RED}Error: No se pudo crear el video${NC}"
    echo "El archivo cast está disponible en: $CAST_FILE"
    echo "Puedes reproducirlo con: asciinema play $CAST_FILE"
fi

echo -e "${GREEN}Proceso completado!${NC}"

#!/bin/bash
#
# MIESC YouTube Video Creator - Fully Automated
# Creates a professional demo video with Daniel voice narration
#
# Usage: ./demo/create_youtube_video.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo/recordings"
AUDIO_DIR="$OUTPUT_DIR/audio_v2"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "=========================================="
echo "  MIESC YouTube Video Creator v2"
echo "  Using Daniel voice (UK English)"
echo "=========================================="
echo -e "${NC}"

cd "$PROJECT_DIR"

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$AUDIO_DIR"

# Voice settings
VOICE="Daniel"
RATE=180  # Words per minute (slightly slower for clarity)

echo -e "${GREEN}Step 1: Generating voice-over segments with $VOICE voice...${NC}"

# Voice-over script - 12 segments for ~90 second video
declare -a VOICEOVER=(
    "MIESC, the Multi-layer Intelligent Evaluation for Smart Contracts. A defense in depth security framework."
    "MIESC combines over 25 security analysis tools across 9 specialized layers."
    "Let's analyze a vulnerable smart contract containing reentrancy and access control issues."
    "The analysis runs through all 9 layers. Static analysis, pattern detection, symbolic execution."
    "Fuzzing, formal verification, and machine learning detection."
    "AI analysis, DeFi security, and dependency scanning."
    "Analysis complete. 5 vulnerabilities detected. 2 critical, 1 high, 1 medium, 1 low."
    "The critical reentrancy vulnerability allows attackers to drain funds from the contract."
    "Each finding includes detailed remediation guidance with code examples."
    "MIESC generates professional audit reports in HTML and PDF formats."
    "Get started today. pip install miesc. Star us on GitHub."
    "MIESC. Making smart contract security accessible to everyone."
)

# Timing in seconds for each segment
declare -a TIMING=(
    0     # Segment 1: 0s
    6     # Segment 2: 6s
    12    # Segment 3: 12s
    18    # Segment 4: 18s
    26    # Segment 5: 26s
    32    # Segment 6: 32s
    38    # Segment 7: 38s
    46    # Segment 8: 46s
    54    # Segment 9: 54s
    62    # Segment 10: 62s
    72    # Segment 11: 72s
    80    # Segment 12: 80s
)

# Generate voice segments
for i in "${!VOICEOVER[@]}"; do
    segment_num=$((i + 1))
    echo "  Generating segment $segment_num..."
    say -v "$VOICE" -r "$RATE" "${VOICEOVER[$i]}" -o "$AUDIO_DIR/voice_${segment_num}.aiff"
    # Convert to wav
    ffmpeg -y -i "$AUDIO_DIR/voice_${segment_num}.aiff" "$AUDIO_DIR/voice_${segment_num}.wav" 2>/dev/null
done

echo -e "${GREEN}Step 2: Creating combined audio track...${NC}"

# Create delayed audio tracks and mix them
FILTER_COMPLEX=""
INPUT_FILES=""
for i in "${!TIMING[@]}"; do
    segment_num=$((i + 1))
    delay_ms=$((${TIMING[$i]} * 1000))
    INPUT_FILES="$INPUT_FILES -i $AUDIO_DIR/voice_${segment_num}.wav"
    if [ $i -eq 0 ]; then
        FILTER_COMPLEX="[0]adelay=${delay_ms}|${delay_ms}[a0]"
    else
        FILTER_COMPLEX="$FILTER_COMPLEX;[$i]adelay=${delay_ms}|${delay_ms}[a$i]"
    fi
done

# Build the amix inputs
AMIX_INPUTS=""
for i in "${!TIMING[@]}"; do
    AMIX_INPUTS="${AMIX_INPUTS}[a$i]"
done
FILTER_COMPLEX="$FILTER_COMPLEX;${AMIX_INPUTS}amix=inputs=${#TIMING[@]}:duration=longest[voice]"

# Generate background music (subtle ambient)
echo "  Creating background music..."
ffmpeg -y -f lavfi -i "anoisesrc=d=90:c=pink:r=44100:a=0.02" \
    -af "lowpass=f=200,highpass=f=50" \
    "$AUDIO_DIR/ambient.wav" 2>/dev/null

# Combine voice with music
echo "  Mixing voice and music..."
eval ffmpeg -y $INPUT_FILES -i "$AUDIO_DIR/ambient.wav" \
    -filter_complex "$FILTER_COMPLEX;[voice][${#TIMING[@]}]amix=inputs=2:duration=longest:weights=1 0.15[out]" \
    -map "[out]" -c:a pcm_s16le "$AUDIO_DIR/final_audio_v2.wav" 2>/dev/null

echo -e "${GREEN}Step 3: Recording terminal demo (90 seconds)...${NC}"

# Activate venv and record
source venv314/bin/activate

# Record with asciinema - slower speed for more detail
echo "  Recording with asciinema..."
asciinema rec "$OUTPUT_DIR/miesc_demo_v2.cast" \
    --overwrite \
    -c "python demo/miesc_video_demo.py --speed 0.25 --no-browser" \
    --cols 130 --rows 40

echo -e "${GREEN}Step 4: Converting to video format...${NC}"

# Convert to GIF
echo "  Converting to GIF..."
agg "$OUTPUT_DIR/miesc_demo_v2.cast" "$OUTPUT_DIR/miesc_demo_v2.gif" \
    --cols 130 --rows 40 --font-size 14 --theme monokai

# Convert to MP4
echo "  Converting to MP4..."
ffmpeg -y -i "$OUTPUT_DIR/miesc_demo_v2.gif" \
    -movflags faststart \
    -pix_fmt yuv420p \
    -vf "fps=30" \
    "$OUTPUT_DIR/miesc_demo_v2.mp4" 2>/dev/null

echo -e "${GREEN}Step 5: Creating subtitles...${NC}"

# Create SRT subtitles synchronized with video
cat > "$PROJECT_DIR/demo/subtitles_v2.srt" << 'EOF'
1
00:00:00,000 --> 00:00:06,000
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts
A Defense-in-Depth Security Framework

2
00:00:06,000 --> 00:00:12,000
25+ security analysis tools across 9 specialized layers

3
00:00:12,000 --> 00:00:18,000
Analyzing VulnerableVault.sol - reentrancy and access control vulnerabilities

4
00:00:18,000 --> 00:00:26,000
Layer 1-3: Static Analysis, Pattern Detection, Symbolic Execution

5
00:00:26,000 --> 00:00:32,000
Layer 4-6: Fuzzing, Formal Verification, ML Detection

6
00:00:32,000 --> 00:00:38,000
Layer 7-9: AI Analysis, DeFi Security, Dependency Scanning

7
00:00:38,000 --> 00:00:46,000
Analysis complete! 5 vulnerabilities: 2 Critical, 1 High, 1 Medium, 1 Low

8
00:00:46,000 --> 00:00:54,000
Critical: Reentrancy vulnerability allows attackers to drain contract funds

9
00:00:54,000 --> 00:00:62,000
Detailed remediation guidance with code examples for each finding

10
00:00:62,000 --> 00:00:72,000
Professional audit reports in HTML and PDF formats

11
00:00:72,000 --> 00:00:80,000
pip install miesc | github.com/fboiero/MIESC

12
00:00:80,000 --> 00:00:90,000
MIESC - Making smart contract security accessible to everyone

EOF

echo -e "${GREEN}Step 6: Adding subtitle bar and subtitles...${NC}"

# Add 80px black bar at top for subtitles
ffmpeg -y -i "$OUTPUT_DIR/miesc_demo_v2.mp4" \
    -vf "pad=iw:ih+80:0:80:black,subtitles=$PROJECT_DIR/demo/subtitles_v2.srt:force_style='FontSize=22,FontName=Arial,PrimaryColour=&HFFFFFF,MarginV=900'" \
    -c:a copy \
    "$OUTPUT_DIR/miesc_demo_v2_subtitled.mp4" 2>/dev/null

echo -e "${GREEN}Step 7: Adding voice-over and music...${NC}"

# Get video duration
VIDEO_DURATION=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$OUTPUT_DIR/miesc_demo_v2_subtitled.mp4" 2>/dev/null)
echo "  Video duration: ${VIDEO_DURATION}s"

# Combine video with audio
ffmpeg -y -i "$OUTPUT_DIR/miesc_demo_v2_subtitled.mp4" \
    -i "$AUDIO_DIR/final_audio_v2.wav" \
    -c:v copy -c:a aac -b:a 192k \
    -map 0:v:0 -map 1:a:0 \
    -shortest \
    "$OUTPUT_DIR/miesc_youtube_final.mp4" 2>/dev/null

echo ""
echo -e "${GREEN}=========================================="
echo "  Video Creation Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${CYAN}Output file: $OUTPUT_DIR/miesc_youtube_final.mp4${NC}"
echo ""
echo -e "${YELLOW}Video specifications:${NC}"
echo "  - Resolution: Terminal recording"
echo "  - Voice: Daniel (UK English)"
echo "  - Duration: ~90 seconds"
echo "  - Subtitles: Synchronized"
echo ""
echo -e "${GREEN}Suggested YouTube metadata:${NC}"
echo ""
echo "Title: MIESC - Smart Contract Security Analysis (25+ Tools, 9 Layers)"
echo ""
echo "Description:"
echo "MIESC (Multi-layer Intelligent Evaluation for Smart Contracts) is a defense-in-depth"
echo "security framework that combines 25+ analysis tools across 9 specialized layers."
echo ""
echo "Features:"
echo "- Static Analysis (Slither, Aderyn, Solhint)"
echo "- Symbolic Execution (Mythril, Manticore)"
echo "- Fuzzing (Echidna, Medusa)"
echo "- Formal Verification (Certora, Halmos)"
echo "- ML Detection & AI Analysis"
echo "- Professional HTML/PDF Audit Reports"
echo ""
echo "Install: pip install miesc"
echo "GitHub: https://github.com/fboiero/MIESC"
echo "Docs: https://fboiero.github.io/MIESC"
echo ""
echo "Tags: smart contract security, solidity, ethereum, blockchain, slither, mythril,"
echo "      security audit, web3, defi, vulnerability detection, formal verification"

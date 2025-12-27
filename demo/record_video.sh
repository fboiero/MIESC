#!/bin/bash
#
# MIESC Video Recording Script
# Automatically records the demo with screen capture
#
# Usage: ./demo/record_video.sh
#
# Requirements:
#   brew install ffmpeg
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/demo/recordings"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/miesc_demo_$TIMESTAMP.mp4"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          MIESC Video Recording Script                         ║"
echo "║          Recording demo for YouTube                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check for ffmpeg
if ! command -v ffmpeg &> /dev/null; then
    echo -e "${YELLOW}ffmpeg not found. Installing...${NC}"
    brew install ffmpeg
fi

# Get screen resolution
SCREEN_RES=$(system_profiler SPDisplaysDataType | grep Resolution | head -1 | awk '{print $2"x"$4}')
echo -e "${GREEN}Screen resolution: $SCREEN_RES${NC}"

echo ""
echo -e "${YELLOW}Instructions:${NC}"
echo "1. The recording will start in 5 seconds"
echo "2. The demo will run automatically"
echo "3. After the demo, the browser will open with the HTML report"
echo "4. Scroll through the report for the video"
echo "5. Press Ctrl+C when you're done to stop recording"
echo ""
echo -e "${CYAN}Output file: $OUTPUT_FILE${NC}"
echo ""

# Countdown
for i in 5 4 3 2 1; do
    echo -e "${YELLOW}Starting in $i...${NC}"
    sleep 1
done

echo -e "${GREEN}Recording started!${NC}"
echo ""

# Start ffmpeg recording in background
# macOS screen capture using avfoundation
ffmpeg -f avfoundation \
    -capture_cursor 1 \
    -framerate 30 \
    -i "1:none" \
    -c:v libx264 \
    -preset ultrafast \
    -crf 18 \
    -pix_fmt yuv420p \
    "$OUTPUT_FILE" &

FFMPEG_PID=$!

# Wait a moment for ffmpeg to start
sleep 2

# Change to project directory
cd "$PROJECT_DIR"

# Activate venv and run demo
source venv314/bin/activate
python demo/miesc_video_demo.py --speed 0.35

# After demo finishes, wait for user to browse the report
echo ""
echo -e "${YELLOW}Demo complete! Now showing the HTML report.${NC}"
echo -e "${YELLOW}Scroll through the report for the video.${NC}"
echo -e "${CYAN}Press Enter when you're done browsing the report...${NC}"
read -r

# Stop recording
echo ""
echo -e "${GREEN}Stopping recording...${NC}"
kill $FFMPEG_PID 2>/dev/null || true
wait $FFMPEG_PID 2>/dev/null || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Recording Complete!                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Video saved to: $OUTPUT_FILE${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Import the video into your editor (iMovie, DaVinci Resolve, etc.)"
echo "2. Add subtitles from: demo/subtitles.srt"
echo "3. Add intro/outro and background music"
echo "4. Export and upload to YouTube"
echo ""
echo -e "${GREEN}Suggested YouTube title:${NC}"
echo "MIESC - Defense-in-Depth Smart Contract Security Analysis (25+ Tools, 9 Layers)"
echo ""
echo -e "${GREEN}Suggested tags:${NC}"
echo "smart contract security, solidity, ethereum, blockchain security, slither, mythril, security audit, web3, defi security"

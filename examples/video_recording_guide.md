# MIESC Video Recording Guide

## Quick Recording Setup

### Option 1: OBS Studio (Recommended)

1. Download OBS Studio: <https://obsproject.com>
2. Set up sources:
   - **Display Capture** for terminal
   - **Window Capture** for browser (HTML report)
3. Import subtitles from `demo/subtitles.srt`

### Option 2: macOS Built-in

```bash
# Start screen recording
# Press Cmd+Shift+5 -> Record Entire Screen

# Run the demo
source venv314/bin/activate && python demo/miesc_video_demo.py --speed 0.3

# Stop recording when done
# Press Cmd+Shift+5 -> Stop
```

### Option 3: Automated Recording (asciinema)

```bash
# Install asciinema
brew install asciinema

# Record terminal session
asciinema rec demo_recording.cast -c "python demo/miesc_video_demo.py --speed 0.3"

# Convert to video (requires agg)
brew install agg
agg demo_recording.cast demo_recording.gif
```

## Video Specifications for YouTube

| Setting | Value |
|---------|-------|
| Resolution | 1920x1080 (Full HD) |
| Frame Rate | 30 fps |
| Format | MP4 (H.264) |
| Audio | Optional background music |
| Length | ~3-4 minutes |

## Recording Steps

1. **Prepare Terminal**

   ```bash
   # Clear terminal and set font size to 16-18pt
   clear

   # Activate environment
   source venv314/bin/activate
   ```

2. **Run Demo with Slower Speed**

   ```bash
   python demo/miesc_video_demo.py --speed 0.3
   ```

3. **When Browser Opens**
   - The HTML report will open automatically
   - Scroll through the report slowly
   - Show the severity chart, findings table, and methodology

4. **Post-Production**
   - Add `demo/subtitles.srt` in your video editor
   - Add intro/outro if desired
   - Add background music (optional)

## Subtitle File

The subtitles are in `demo/subtitles.srt` - import into your video editor.

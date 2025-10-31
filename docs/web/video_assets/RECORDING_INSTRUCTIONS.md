# Instructions for Recording the MIESC Console Demo

## 🎬 Quick Start

### 1. Setup Your Terminal (2 minutes)

**Configure Terminal Appearance:**
```bash
# Open Terminal Preferences (Cmd+,)
# Profile → Text:
#   - Font: Menlo Regular 16pt (or Monaco 16pt)
#   - Background: Black or Dark theme
#   - Cursor: Block
#   - Enable "Antialias text"

# OR use a pre-made theme:
# Download Dracula theme for Terminal
# https://draculatheme.com/terminal
```

**Set Window Size:**
- Resize terminal to fill most of your screen
- Recommended: 160 columns × 40 rows
- Command: `printf '\e[8;40;160t'`

### 2. Prepare for Recording (1 minute)

```bash
# Navigate to MIESC directory
cd /Users/fboiero/Documents/GitHub/MIESC

# Clear terminal
clear

# Test the demo script first (without recording)
./video_assets/record_demo.sh slow
```

### 3. Start Recording with OBS Studio

**OBS Setup:**

1. **Create Scene:**
   - Scene Name: "Terminal Demo"
   - Click "+" in Sources
   - Select "Window Capture"
   - Choose your Terminal window

2. **Adjust Capture:**
   - Right-click source → Transform → Fit to Screen
   - Or manually resize to show only terminal (no menu bar)

3. **Recording Settings:**
   - Settings → Output
   - Recording Format: MP4
   - Encoder: x264 (or Hardware if available)
   - Bitrate: 10,000 Kbps
   - Resolution: 1920x1080
   - FPS: 60

4. **Audio (Optional):**
   - If recording keyboard sounds, enable microphone
   - Lower mic volume to -18dB (subtle background)

### 4. Record the Demo

**Full Recording Sequence:**

```bash
# 1. Start OBS Recording (Hotkey: Cmd+Shift+R or click "Start Recording")

# 2. In terminal, run:
clear
./video_assets/record_demo.sh slow

# 3. Let it run completely (approx 90 seconds)

# 4. Stop OBS Recording when done
```

**That's it!** The script handles everything automatically.

---

## 🎯 Recording Modes

### Slow Mode (Recommended for Video)
```bash
./video_assets/record_demo.sh slow
```
- Duration: ~90 seconds
- Best for recording (easy to watch)
- Natural pauses between steps
- Perfect timing for voiceover

### Fast Mode (Quick Preview)
```bash
./video_assets/record_demo.sh fast
```
- Duration: ~30 seconds
- Good for testing
- Too fast for final video

---

## 🎨 What the Script Does

The demo automatically shows:

### ✅ Phase 1: Initialization (10s)
- MIESC banner and version
- Command being run
- Configuration loading
- Contract validation
- Context Bus initialization

### ✅ Phase 2: Layer 1 - Static Analysis (15s)
- **Slither**: 23 findings (reentrancy, access control, style)
- **Aderyn**: 12 findings (missing events, unsafe calls)
- **Solhint**: 8 findings (style issues)

### ✅ Phase 3: Layer 2 - Dynamic Testing (10s)
- **Echidna**: Fuzzing with 1000 test cases
- Property violations detected

### ✅ Phase 4: Layer 3 - Symbolic Execution (15s)
- **Mythril**: Exploring state space, 5 exploitable paths
- **Manticore**: 3 confirmed exploits
- Reentrancy confirmed (SWC-107)

### ✅ Phase 5: Layer 5 - AI Analysis (15s)
- Cross-referencing 51 findings
- Identifying 8 duplicates
- Filtering 37 false positives (72.5%)
- Root cause analysis

### ✅ Phase 6: Layer 6 - Policy Compliance (8s)
- ISO/IEC 27001
- OWASP SC Top 10
- SWC Registry
- NIST SP 800-218

### ✅ Phase 7: Results Summary (20s)
- **Raw findings**: 51 total
- **After AI filtering**: 6 actionable findings
- **CRITICAL (1)**: Reentrancy with full details
- **HIGH (2)**: Access control, unsafe transfer
- **MEDIUM (3)**: Validation issues
- **Statistics**: 88.2% reduction, 89.47% precision

### ✅ Phase 8: Report Generation (5s)
- JSON, HTML, PDF reports generated
- Compliance matrix created

---

## 📊 Visual Features

The script includes:

- ✨ **Color-coded output**:
  - 🔴 Red for critical issues
  - 🟠 Yellow for high/warnings
  - 🟢 Green for success
  - 🔵 Blue for info
  - 🟣 Purple for symbolic execution

- 🎯 **Icons throughout**:
  - 🛡️ Shield (MIESC branding)
  - 🔍 Search (analysis tools)
  - 🤖 Robot (AI agent)
  - ✓ Checkmarks (success)
  - ⚡ Lightning (speed)
  - 📊 Charts (statistics)

- 📦 **Formatted sections**:
  - Box headers for each phase
  - Progress indicators
  - Indented hierarchies
  - Aligned text

- ⏱️ **Perfect timing**:
  - Natural pauses between steps
  - Realistic tool execution times
  - Smooth flow for narration

---

## 🎥 Pro Recording Tips

### Before Recording

1. **Clean Your Desktop**
   ```bash
   # Hide desktop icons (macOS)
   defaults write com.apple.finder CreateDesktop false
   killall Finder

   # Restore later:
   defaults write com.apple.finder CreateDesktop true
   killall Finder
   ```

2. **Disable Notifications**
   - Enable "Do Not Disturb" mode
   - Close Slack, Discord, email apps

3. **Close Unnecessary Apps**
   - Quit everything except Terminal and OBS

4. **Test Run**
   - Run the script 2-3 times before recording
   - Verify colors display correctly
   - Check window size fits well

### During Recording

1. **Don't Touch Anything**
   - Script is fully automated
   - No keyboard/mouse input needed
   - Let it run to completion

2. **Watch for Issues**
   - If text scrolls off screen → window too small
   - If colors don't show → check terminal theme
   - If script stops → might need to Ctrl+C and restart

3. **Record Multiple Takes**
   - Record 2-3 complete runs
   - Pick the best one in editing

### After Recording

1. **Preview the Recording**
   - Watch entire video
   - Check for:
     - Text is readable
     - Colors are vibrant
     - No stuttering/lag
     - Good frame rate

2. **Save the File**
   - Save as: `01_Raw_Footage/terminal_demo_full.mov`
   - Keep original (don't overwrite)

---

## 🛠️ Troubleshooting

### Colors Don't Show
**Problem:** Output is black and white, no colors

**Solution:**
```bash
# Check TERM variable
echo $TERM  # Should be xterm-256color

# If not, set it:
export TERM=xterm-256color

# Add to ~/.zshrc or ~/.bash_profile to make permanent:
echo 'export TERM=xterm-256color' >> ~/.zshrc
```

### Icons Don't Display
**Problem:** Seeing boxes (□) instead of emojis

**Solution:**
- Use macOS Terminal (best emoji support)
- Or iTerm2 with emoji font installed
- Avoid SSH/remote terminals

### Text Is Too Small
**Problem:** Can't read text in recording

**Solution:**
```bash
# Increase font size in Terminal
# Preferences → Profile → Text → Font Size: 18pt or 20pt
```

### Script Runs Too Fast/Slow
**Problem:** Timing is off

**Solution:**
```bash
# For slower (more pauses):
./video_assets/record_demo.sh slow

# To customize timing, edit the script:
# Lines 20-26 have DELAY_SHORT, DELAY_MEDIUM, DELAY_LONG
```

### Recording Looks Choppy
**Problem:** Video stutters or lags

**Solution:**
- Close other apps (free up CPU/RAM)
- Lower OBS encoding preset (veryfast)
- Or record at 30fps instead of 60fps
- Check Activity Monitor for CPU usage

### Terminal Window Too Small
**Problem:** Text wraps or cuts off

**Solution:**
```bash
# Resize window to 160 columns:
printf '\e[8;40;160t'

# Or manually drag window corners
# Should be ~1600px wide on 1920px screen
```

---

## 🎬 Example Recording Flow

Here's exactly what to do:

```bash
# 1. Open Terminal (Cmd+Space, type "Terminal")

# 2. Set up appearance
# Terminal → Preferences → Profiles
# Choose "Homebrew" or create custom dark theme

# 3. Set font size
# Text tab → Font: Menlo 16pt

# 4. Resize window
# Drag to fill most of screen, leaving room for OBS controls

# 5. Navigate to project
cd /Users/fboiero/Documents/GitHub/MIESC

# 6. Test run (not recorded)
clear
./video_assets/record_demo.sh slow

# Watch it run, verify it looks good

# 7. Open OBS Studio
# Create scene with Window Capture
# Select Terminal window

# 8. Start recording in OBS (Cmd+Shift+R)

# 9. In Terminal, run:
clear
./video_assets/record_demo.sh slow

# 10. Wait for completion (~90 seconds)

# 11. Stop recording in OBS

# 12. Find video file:
# OBS default location: ~/Movies/
# File name: YYYY-MM-DD HH-MM-SS.mov
```

---

## 📝 Script Timing Breakdown

For planning your voiceover:

| Time | Section | What Happens |
|------|---------|--------------|
| 0-10s | Init | MIESC starts, loads config |
| 10-25s | Layer 1 | Slither, Aderyn, Solhint run |
| 25-35s | Layer 2 | Echidna fuzzing |
| 35-50s | Layer 3 | Mythril, Manticore symbolic exec |
| 50-65s | Layer 5 | AI filtering, root cause |
| 65-73s | Layer 6 | Compliance checking |
| 73-93s | Summary | Results, statistics, next steps |

Total: ~90 seconds

---

## 🎯 Expected Output

Your recording should show:

1. ✅ Professional-looking terminal with dark theme
2. ✅ Colorful output with icons
3. ✅ Smooth progression through 6 layers
4. ✅ Clear statistics (51 → 6 findings)
5. ✅ Detailed critical vulnerability info
6. ✅ Final success message

**File size:** ~50-100MB for 90 seconds at 1080p 60fps

---

## 🚀 Next Steps

After recording the console demo:

1. **Preview** - Watch the recording, check quality
2. **Trim** - Cut first/last few seconds in editing
3. **Color Grade** - Slight contrast boost (optional)
4. **Combine** - Integrate with other scenes (website, Claude Desktop)
5. **Add Voiceover** - Narrate over the demo
6. **Export** - Final video ready!

---

## 💡 Pro Tip

**Record 3 takes:**
- Take 1: Test run, might have issues
- Take 2: Usually best
- Take 3: Backup

Then pick the best one in editing. Having multiple takes gives you options!

---

**Ready to record? Let's go! 🎬**

Questions? Check the main VIDEO_PRODUCTION_GUIDE.md or open an issue on GitHub.

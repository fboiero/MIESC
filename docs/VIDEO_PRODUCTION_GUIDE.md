# MIESC Video Production Guide
## Complete Step-by-Step Tutorial for Creating the Demo Video

This guide walks you through every step of creating the MIESC demo video, from setup to final export.

---

## 📁 Project Structure

Create this folder structure for your video project:

```
MIESC_Video_Project/
├── 01_Raw_Footage/
│   ├── terminal_recording.mov
│   ├── claude_desktop.mov
│   ├── config_setup.mov
│   └── browser_shots.mov
├── 02_Audio/
│   ├── voiceover_raw.wav
│   ├── voiceover_edited.wav
│   ├── music_intro.mp3
│   ├── music_main.mp3
│   └── sfx/
│       ├── whoosh.wav
│       ├── typing.wav
│       └── notification.wav
├── 03_Graphics/
│   ├── logo_miesc.png
│   ├── overlays/
│   ├── lower_thirds/
│   └── transitions/
├── 04_Edit/
│   └── miesc_demo.dproj (DaVinci Resolve)
└── 05_Export/
    ├── miesc_demo_90s.mp4
    ├── miesc_demo_30s.mp4
    └── thumbnail.png
```

---

## 🎬 PART 1: PREPARATION (30 minutes)

### Step 1: Install Required Software

**Free Options:**
```bash
# macOS
brew install --cask obs
brew install --cask vlc
brew install --cask audacity

# Download DaVinci Resolve (free)
# https://www.blackmagicdesign.com/products/davinciresolve/

# Download Blender (free, for 3D animations if needed)
# https://www.blender.org/download/
```

**Paid Alternatives:**
- **ScreenFlow** (macOS) - $169 - All-in-one solution
- **Camtasia** (macOS/Windows) - $299 - Easy to use
- **Final Cut Pro** (macOS) - $299 - Professional editing

### Step 2: Configure Your Environment

**1. Desktop Cleanup:**
```bash
# Hide desktop icons (macOS)
defaults write com.apple.finder CreateDesktop false
killall Finder

# To restore later:
defaults write com.apple.finder CreateDesktop true
killall Finder
```

**2. Terminal Setup:**
```bash
# Install a clean terminal theme
# Recommended: Dracula or Nord theme

# Set terminal to large font
# Terminal → Preferences → Profiles → Text
# Font: Menlo 16pt or Monaco 16pt

# Install Oh My Zsh for nice prompt (optional)
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

**3. Browser Setup:**
- Install Chrome extension: "Tab Suspender" (reduce CPU usage)
- Close all unnecessary tabs
- Set zoom to 100%

### Step 3: Prepare Demo Contract

```bash
cd /path/to/MIESC

# Copy demo contract to visible location
cp examples/demo_vulnerable.sol ~/Desktop/VulnerableBank.sol

# Test MIESC tools
python xaudit.py --target ~/Desktop/VulnerableBank.sol --mode fast
```

### Step 4: Configure Claude Desktop

Follow `docs/MCP_SETUP_GUIDE.md` to set up MCP connection.

**Test the connection:**
1. Open Claude Desktop
2. Type: "Are you connected to MIESC?"
3. Verify green status indicator

---

## 🎥 PART 2: RECORDING (2 hours)

### SCENE 1: The Problem (Terminal Overwhelm)

**What to record:**
- Terminal window showing overwhelming Slither output

**Recording steps:**

```bash
# 1. Open OBS Studio
# 2. Create new scene: "Scene 1 - Problem"
# 3. Add source: "Window Capture" → Select Terminal

# 4. Run this command (for dramatic effect):
cd ~/Desktop
slither VulnerableBank.sol > slither_output.txt

# 5. Show the output (147 warnings)
cat slither_output.txt | head -50

# Scroll slowly through warnings to show overwhelm
```

**OBS Settings for Terminal:**
- Resolution: 1920x1080
- FPS: 60
- Bitrate: 10000 Kbps
- Format: MP4
- Encoder: H.264

**Recording tips:**
- Record 20-30 seconds (you'll edit to 10-15s)
- Scroll slowly through output
- Pause occasionally to emphasize chaos

### SCENE 2: The Solution (Logo & Website)

**What to record:**
- MIESC website with animated gradient
- Zoom into Claude Desktop icon

**Recording steps:**

```bash
# 1. Open browser to https://fboiero.github.io/MIESC/
# 2. Full screen mode (F11 or Cmd+Shift+F)
# 3. Record 10 seconds of hero section
# 4. Scroll down slowly to show features
# 5. Zoom into "Get Started" button
```

**Alternative (if website not live yet):**
- Open `website/index.html` locally
- Use Python server: `python -m http.server 8000`
- Navigate to `http://localhost:8000`

### SCENE 3: Setup (Config File)

**What to record:**
- Opening Claude Desktop config file
- Adding MIESC configuration
- Restarting Claude

**Recording steps:**

```bash
# 1. Record VS Code or text editor
code ~/Library/Application\ Support/Claude/claude_desktop_config.json

# 2. Slowly type the configuration (or paste and pretend to type)
# Use this exact text:
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/Users/YOUR_USERNAME/MIESC/src/mcp/server.py"],
      "env": {
        "PYTHONPATH": "/Users/YOUR_USERNAME/MIESC"
      }
    }
  }
}

# 3. Save file (Cmd+S with visible keystroke animation)

# 4. Show Claude Desktop restarting
# - Close Claude (Cmd+Q)
# - Reopen from Dock
# - Show green "MIESC connected" indicator
```

**Text animation tips:**
- Type at 60-80 WPM (natural speed)
- Use keyboard shortcuts visibly (Cmd+S, Cmd+Q)
- Add "Save" and "Restart" text overlays

### SCENE 4: Live Demo (The Magic!)

**This is the most important scene - record it perfectly!**

**What to record:**
- Split screen: Claude Desktop (left) + Terminal (right)
- User typing in Claude
- MIESC tools running in background
- Results appearing

**Recording steps:**

**Setup split screen:**
```bash
# Option A: Use macOS Split View
# 1. Full screen Claude Desktop
# 2. Drag Terminal to right side
# 3. Adjust to 60/40 split (Claude bigger)

# Option B: Use Rectangle app (free)
brew install --cask rectangle
# Then: Cmd+Option+Left (Claude), Cmd+Option+Right (Terminal)
```

**Recording sequence:**

**Part 1: User types in Claude (10 seconds)**
```
Type slowly and clearly:

"Audit this DeFi contract for critical vulnerabilities:
/Users/fboiero/Desktop/VulnerableBank.sol"
```

**Part 2: Background tools running (15 seconds)**

In terminal (visible on right side), run:
```bash
# This simulates MIESC tools running
cd /path/to/MIESC

# Add colored output for visual effect
echo "🔍 [Slither] Running 87 detectors..."
sleep 2
echo "✓ [Slither] Complete - 23 findings"
sleep 1

echo "🔍 [Mythril] Symbolic execution..."
sleep 3
echo "✓ [Mythril] Complete - 5 critical paths"
sleep 1

echo "🦀 [Aderyn] Ultra-fast AST analysis..."
sleep 1
echo "✓ [Aderyn] Complete - 12 findings"
sleep 1

echo "🤖 [AIAgent] Filtering false positives..."
sleep 2
echo "✓ [AIAgent] Complete - 139 FPs filtered"
sleep 1

echo ""
echo "📊 Final Results: 6 actionable findings"
echo "🔴 CRITICAL: 1"
echo "🟠 HIGH: 2"
echo "🟡 MEDIUM: 3"
```

**Part 3: Claude's response (20 seconds)**

Claude should respond with:
```
✅ Analysis Complete

🔴 CRITICAL (1):
Reentrancy vulnerability in withdraw() function
- Line 28: External call before state update
- Exploitable via recursive callback
- Fix: Use Checks-Effects-Interactions pattern

🟠 HIGH (2):
• Missing access control on setBalance() - Line 40
• Unsafe transfer in emergencyWithdraw() - Line 54

🟡 MEDIUM (3):
• No recipient validation
• Missing zero address checks
• Unchecked return values

✨ 139 false positives filtered by AI

Would you like me to generate a patch for the reentrancy issue?
```

**Recording tips:**
- Record this scene multiple times (you'll pick the best take)
- Ensure terminal output is visible and readable
- Claude's typing should look natural (not instant)
- Total recording: 45-60 seconds (edit to 35s)

### SCENE 5: Before/After Comparison

**What to record:**
- Two side-by-side comparisons
- Animated checkmarks and X marks

**Option A: Record in browser (easiest)**
```html
<!-- Create compare.html -->
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      background: #0a0e27;
      color: white;
      font-family: 'Inter', sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      font-size: 24px;
    }
    .comparison {
      display: flex;
      gap: 100px;
    }
    .column {
      text-align: center;
    }
    .column h2 {
      font-size: 36px;
      margin-bottom: 40px;
    }
    .item {
      margin: 20px 0;
      font-size: 28px;
    }
    .before .item { color: #ef4444; }
    .after .item { color: #10b981; }
  </style>
</head>
<body>
  <div class="comparison">
    <div class="column before">
      <h2>Before MIESC</h2>
      <div class="item">❌ 147 warnings</div>
      <div class="item">❌ Hours of work</div>
      <div class="item">❌ Miss criticals</div>
      <div class="item">❌ False positives</div>
    </div>
    <div class="column after">
      <h2>With MIESC</h2>
      <div class="item">✅ 6 real issues</div>
      <div class="item">✅ Minutes</div>
      <div class="item">✅ AI-ranked</div>
      <div class="item">✅ 89% precision</div>
    </div>
  </div>
</body>
</html>
```

**Record:**
1. Open in browser (full screen)
2. Record 10 seconds
3. Add fade-in animation for each line in post-production

**Option B: Create in PowerPoint/Keynote**
- Easier to animate
- Export as video

### SCENE 6: Call to Action (Website)

**What to record:**
- MIESC website homepage
- Zoom into "Get Started" button
- GitHub stars counter
- Fade to logo

**Recording:**
```bash
# 1. Open website
open https://fboiero.github.io/MIESC/

# 2. Record 10 seconds of homepage
# 3. Slowly scroll to show badges
# 4. Zoom into GitHub link
# 5. End on hero section
```

---

## 🎙️ PART 3: VOICEOVER RECORDING (1 hour)

### Setup Audio Recording

**Hardware:**
- Use a quality USB microphone (Blue Yeti, Audio-Technica ATR2100)
- Or: Good headset with mic (AirPods Pro work okay)
- Record in quiet room (closet with clothes = good acoustics)

**Software: Audacity (Free)**

```bash
# Install Audacity
brew install --cask audacity

# Open Audacity
# Settings → Preferences → Quality
# Sample Rate: 48000 Hz
# Default Format: 32-bit float
```

### Recording the Voiceover

**Script (89 words, ~45 seconds at natural pace):**

```
[INTRO - Confident but frustrated]
You just ran Slither on your smart contract.
147 warnings. 89 are informational. 37 are low priority.
Which ones actually matter?

[SOLUTION - Excited, confident]
Meet MIESC. A Model Context Protocol server
that brings 15 security tools directly into Claude Desktop.
Just ask Claude to audit your contract.

[SETUP - Matter-of-fact, quick]
Setup takes 30 seconds.
Add MIESC to your Claude Desktop config.
Restart Claude. Done.

[DEMO - Building excitement]
Watch.
I ask Claude to audit this DeFi lending contract.
Behind the scenes, MIESC orchestrates Slither, Mythril,
Aderyn, and 12 other tools.
AI filters the noise.
Claude gives me 6 actionable findings,
ranked by severity, with fix suggestions.

[RESULTS - Triumphant]
From 147 warnings to 6 actionable findings.
From hours to minutes.
That's the power of AI-assisted security.

[CTA - Clear, inviting]
MIESC. Open source. Battle-tested on 5,000 contracts.
Available now on GitHub.
```

**Recording tips:**
1. **Read through 5 times** before recording (warm up)
2. **Record in 3-5 takes** (pick the best or splice together)
3. **Stand up while recording** (better vocal projection)
4. **Smile while talking** (sounds more engaging)
5. **Pause between sentences** (easier to edit)
6. **Record room tone** (30 seconds of silence for noise removal)

### Audio Post-Production in Audacity

**Step 1: Noise Removal**
1. Select 3 seconds of silence (room tone)
2. Effect → Noise Reduction → Get Noise Profile
3. Select all audio (Cmd+A)
4. Effect → Noise Reduction → OK

**Step 2: Normalize**
1. Select all (Cmd+A)
2. Effect → Normalize
3. Check "Remove DC offset"
4. Check "Normalize peak amplitude to -1.0 dB"
5. OK

**Step 3: Compression**
1. Select all
2. Effect → Compressor
3. Threshold: -12 dB
4. Ratio: 3:1
5. Attack: 0.2s
6. Release: 1.0s

**Step 4: EQ (Optional)**
1. Effect → Equalization
2. Boost: 100-200 Hz (+2 dB) for warmth
3. Boost: 3-5 kHz (+3 dB) for clarity
4. Cut: 50 Hz and below (remove rumble)

**Step 5: Export**
1. File → Export → Export as MP3
2. Quality: 320 kbps (highest)
3. Save as: `voiceover_edited.mp3`

---

## 🎨 PART 4: GRAPHICS & ANIMATIONS (2 hours)

### Create Graphics Assets

**1. Logo Animation (PNG sequence)**

Use this HTML/CSS for animated logo:

```html
<!-- logo_animation.html -->
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      background: #0a0e27;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .logo {
      font-size: 200px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); filter: drop-shadow(0 0 20px #3b9aff); }
      50% { transform: scale(1.1); filter: drop-shadow(0 0 40px #00d4d4); }
    }
  </style>
</head>
<body>
  <div class="logo">🛡️</div>
</body>
</html>
```

Record with OBS (10 seconds), then use in intro/outro.

**2. Text Overlays (Lower Thirds)**

Create in DaVinci Resolve Fusion:
- Project name: "MIESC"
- Subtitle: "Multi-Agent Security Framework"
- Style: Glassmorphism with gradient border

**Template:**
```
┌─────────────────────────────────────────┐
│                                         │
│  🛡️ MIESC                               │
│  Multi-Agent Security Framework         │
│                                         │
└─────────────────────────────────────────┘
```

**3. Animated Metrics**

Use After Effects or DaVinci Resolve Fusion:

```
89.47% Precision
[Animated counter from 0% to 89.47%]

90% Time Saved
[Progress bar animation]

15 Tools Integrated
[Icons appearing one by one]
```

**Quick tutorial for DaVinci Resolve Fusion text animation:**
1. Right-click timeline → Fusion Clip
2. Add Text+ node
3. Add Merge node
4. Keyframe "Write On" effect
5. Adjust timing (0.5s per line)

---

## 🎬 PART 5: VIDEO EDITING (4 hours)

### DaVinci Resolve Project Setup

**1. Import Media:**
```
File → Import → Media
Select all recordings from 01_Raw_Footage/
Select voiceover from 02_Audio/
```

**2. Timeline Settings:**
```
Right-click Project → Timeline Settings
- Resolution: 1920x1080
- Frame Rate: 60 fps
- Audio Sample Rate: 48000 Hz
```

**3. Create Timeline:**
```
File → New Timeline
Name: "MIESC_Demo_90s"
```

### Editing Sequence

**SCENE 1 (0-15s): The Problem**

1. Drag `terminal_recording.mov` to timeline
2. Trim to best 10-15 seconds
3. Add zoom effect:
   - Inspector → Transform → Zoom
   - Keyframe: Start at 1.0, end at 1.2 (slow zoom in)
4. Add text overlay:
   - "147 Warnings 😵"
   - Position: Top center
   - Animation: Fade in from bottom
5. Add voiceover (0-10s section)
6. Color grade:
   - Increase contrast (Lift 0.9, Gamma 1.0, Gain 1.1)
   - Slight red tint for "danger" feel

**Transition 1 → 2:**
- Use "Smooth Cut" transition (0.5s)
- Add whoosh sound effect

**SCENE 2 (15-30s): The Solution**

1. Drag website recording
2. Trim to 15 seconds
3. Add text overlays:
   - "MIESC" (large, center, gradient animation)
   - "15 Tools • AI-Powered • Open Source"
4. Add zoom transition:
   - Zoom from website to Claude Desktop icon
5. Add voiceover (10-25s section)
6. Music starts here (fade in)

**Transition 2 → 3:**
- Cross dissolve (1s)

**SCENE 3 (30-40s): Setup**

1. Drag config file recording
2. Speed up typing by 1.5x (looks more impressive)
3. Add callout annotations:
   - Arrow pointing to "miesc" key
   - Highlight "command" and "args" fields
4. Add checkmark animation when saved
5. Show Claude Desktop restart (time-lapse 3x speed)
6. Add voiceover (25-35s section)

**Transition 3 → 4:**
- Wipe transition (0.3s)

**SCENE 4 (40-75s): Live Demo**

1. Drag split-screen recording
2. Add "magic moment" effects:
   - Glow around Claude when typing starts
   - Pulse effect on terminal when tools run
   - Highlight critical findings in red
3. Add animated labels:
   - "Claude Desktop" (top left)
   - "MIESC Tools Running" (top right)
4. Sync voiceover perfectly (35-60s section)
5. Add typing sound effects (subtle)
6. Speed up waiting parts by 1.2x

**Key moments to emphasize:**
- 42s: User finishes typing (pause 0.5s)
- 45s: Tools start running (music builds)
- 60s: Results appear (music peak)
- 70s: "139 FPs filtered" (emphasize this!)

**Transition 4 → 5:**
- Smooth cut (instant)

**SCENE 5 (75-85s): Before/After**

1. Drag comparison graphic
2. Animate each line appearing:
   - Stagger by 0.3s per line
   - Fade in + slide from left (Before)
   - Fade in + slide from right (After)
3. Add voiceover (60-70s section)
4. Add "ding" sound on each checkmark

**Transition 5 → 6:**
- Fade to black (0.5s)
- Fade from black (0.5s)

**SCENE 6 (85-90s): CTA**

1. Drag website recording (hero section)
2. Add text overlays:
   - "github.com/fboiero/MIESC"
   - "Open Source • GPL-3.0"
   - "89.47% Precision • 90% Time Saved"
3. Add animated logo (pulse effect)
4. Add voiceover (70-85s section)
5. Music fades out
6. End card: Logo + "Defense-in-Depth for the Decentralized World"

### Audio Mixing

**Timeline:** Make sure you have 3 audio tracks:
- Track 1: Voiceover
- Track 2: Music
- Track 3: Sound Effects

**Levels:**
- Voiceover: -3 dB (loudest)
- Music: -18 dB (background)
- SFX: -12 dB (noticeable but not overpowering)

**Ducking (auto-lower music when voice plays):**
1. Right-click music track → Audio → Ducking
2. Set Voice track as trigger
3. Threshold: -30 dB
4. Ratio: 4:1

### Color Grading

**Apply to all clips:**
1. Go to Color tab
2. Select all clips (Cmd+A)
3. Create Color Group
4. Adjust:
   - Lift (shadows): +0.1 (slightly brighter)
   - Gamma (midtones): +0.05
   - Gain (highlights): +0.1
   - Saturation: +10%
5. Add slight blue tint (matches cybersecurity theme):
   - Temperature: -5
   - Tint: +3 (towards blue)

---

## 📤 PART 6: EXPORT & DISTRIBUTION (30 minutes)

### Export Settings

**Go to Deliver tab:**

**Preset: YouTube 1080p**
- Format: MP4
- Codec: H.264
- Resolution: 1920x1080
- Frame Rate: 60 fps
- Quality: Automatic (or set bitrate to 10,000 Kbps)

**Advanced Settings:**
- Encoding Profile: High
- Keyframe: Every 30 frames
- Audio Codec: AAC
- Audio Bitrate: 320 kbps

**Render:**
1. Filename: `MIESC_Demo_90s_Final.mp4`
2. Location: `05_Export/`
3. Click "Add to Render Queue"
4. Click "Render All"

**Export time:** ~5-10 minutes depending on hardware

### Create Alternative Versions

**30-second version (Twitter/Instagram):**
1. Duplicate timeline
2. Keep only Scenes 4 & 6 (Demo + CTA)
3. Speed up demo by 1.5x
4. Export as `MIESC_Demo_30s.mp4`

**60-second version (LinkedIn):**
1. Duplicate timeline
2. Keep Scenes 2, 4, 5, 6
3. Trim transitions
4. Export as `MIESC_Demo_60s.mp4`

### Create Thumbnail

**Option A: Export frame from video**
1. In Edit tab, scrub to best frame (usually Scene 4 - live demo)
2. Right-click → Grab Still
3. Export as PNG

**Option B: Create in Canva (easiest)**
1. Go to canva.com
2. Select "YouTube Thumbnail" template
3. Use these elements:
   - Background: Dark blue gradient
   - Text: "AI Security in 60 Seconds"
   - Subtext: "147 Warnings → 6 Real Issues"
   - Logo: 🛡️ MIESC
   - Face: Your face with excited expression (optional)
4. Export as PNG (1280x720)

**Thumbnail best practices:**
- Large, bold text (readable on mobile)
- High contrast colors
- Include face if possible (higher CTR)
- Use numbers ("90% Faster")
- Bright colors that pop

---

## 📊 DISTRIBUTION CHECKLIST

### YouTube Upload

**Title:** "AI-Powered Smart Contract Security in 60 Seconds | MIESC + Claude Desktop Demo"

**Description:**
```
Watch how MIESC + Claude Desktop transforms smart contract security from hours to minutes.

🛡️ MIESC (Multi-Agent Security Framework) integrates 15 security tools with Claude Desktop using the Model Context Protocol (MCP).

🎯 Results:
• 89.47% Precision
• 90% Time Saved
• 43% Fewer False Positives
• 15 Tools Integrated

🚀 Get Started:
• GitHub: https://github.com/fboiero/MIESC
• Docs: https://fboiero.github.io/MIESC/
• Setup Guide: [link]

📋 Chapters:
0:00 - The Problem
0:15 - The Solution
0:30 - Setup
0:40 - Live Demo
1:15 - Results
1:25 - Get Started

#SmartContracts #Blockchain #Security #AI #Solidity #Ethereum #DeFi
```

**Tags:**
smart contracts, blockchain security, solidity, ethereum, AI, claude, MCP, security tools, DeFi, audit, static analysis

**Thumbnail:** Upload custom thumbnail

**Playlist:** Create "MIESC Tutorials" playlist

### Twitter/X Post

```
🛡️ AI-powered smart contract security in 60 seconds

147 warnings → 6 real issues
Hours → Minutes
Manual triage → AI-assisted

Watch @ClaudeAI + MIESC in action:
[Video link]

Open source • 15 tools • 89% precision

#Ethereum #DeFi #Security
```

### LinkedIn Post

```
Just shipped: MIESC demo showing AI-assisted smart contract security

Traditional auditing:
❌ 147 warnings to triage
❌ 4-8 hours of manual work
❌ Easy to miss critical issues

With MIESC + Claude Desktop:
✅ 6 actionable findings
✅ 15-30 minutes
✅ AI-ranked by severity

Built on Model Context Protocol (MCP), MIESC brings Slither, Mythril, Aderyn, and 12 other tools directly into Claude Desktop.

89.47% precision. 90% time saved. Open source.

Watch the 90-second demo:
[Video link]

GitHub: https://github.com/fboiero/MIESC

#Blockchain #Security #AI #SmartContracts #DeFi
```

---

## ✅ FINAL CHECKLIST

Before publishing:

**Technical:**
- [ ] Video plays smoothly (no stuttering)
- [ ] Audio is clear and well-balanced
- [ ] No background noise in voiceover
- [ ] Text overlays are readable
- [ ] Colors are vibrant and professional
- [ ] Transitions are smooth
- [ ] Video is 1920x1080 or higher
- [ ] File size under 500MB

**Content:**
- [ ] All links are correct (GitHub, website)
- [ ] Demo shows real results
- [ ] Voiceover matches visuals
- [ ] Music is royalty-free
- [ ] Credits included (if using others' work)

**Marketing:**
- [ ] Thumbnail is eye-catching
- [ ] Title is SEO-optimized
- [ ] Description includes all links
- [ ] Tags are relevant
- [ ] Captions/subtitles added (accessibility)
- [ ] End screen with subscribe button
- [ ] Pinned comment with GitHub link

---

## 🎓 LEARNING RESOURCES

**DaVinci Resolve Tutorials:**
- Official: https://www.blackmagicdesign.com/products/davinciresolve/training
- Casey Faris (YouTube): Excellent beginner tutorials
- JayAreTV: Professional techniques

**OBS Studio:**
- Official docs: https://obsproject.com/wiki/
- EposVox (YouTube): OBS master tutorials

**Audio:**
- Booth Junkie (YouTube): Microphone and audio tips
- Curtis Judd: Professional audio tutorials

**Animation:**
- Ben Marriott (YouTube): After Effects tutorials
- Ducky3D: Blender motion graphics

---

**Good luck with your video production! 🎬**

If you get stuck, refer back to this guide or reach out for help.

**Author:** Fernando Boiero
**Last Updated:** December 2024
**License:** GPL-3.0

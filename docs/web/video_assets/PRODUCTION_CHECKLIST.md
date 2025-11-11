# MIESC Video Production Checklist
## Your Complete Step-by-Step Guide

Use this checklist to track your progress through the video production process.

---

## 📋 PRE-PRODUCTION

### Environment Setup
- [ ] Desktop cleaned (no personal files visible)
- [ ] Notifications disabled (Do Not Disturb mode)
- [ ] Terminal configured (clean theme, large font 16pt+)
- [ ] Browser tabs closed (only MIESC website)
- [ ] Claude Desktop installed and configured
- [ ] MIESC MCP connection tested and working
- [ ] Demo contract ready (`examples/demo_vulnerable.sol`)

### Software Installation
- [ ] OBS Studio installed
- [ ] DaVinci Resolve (or ScreenFlow/Camtasia) installed
- [ ] Audacity installed
- [ ] VLC player installed (for previewing)
- [ ] Chrome/Firefox with clean profile

### Content Preparation
- [ ] Video script read through 3+ times
- [ ] Voiceover script printed/visible
- [ ] Terminal commands tested (`video_assets/terminal_commands.sh`)
- [ ] HTML animations tested:
  - [ ] `compare.html` opens correctly
  - [ ] `logo_animation.html` opens correctly
- [ ] Music downloaded (royalty-free)
- [ ] Sound effects downloaded (whoosh, typing, ding)

---

## 🎥 RECORDING

### OBS Setup
- [ ] Resolution set to 1920x1080
- [ ] Frame rate set to 60 FPS
- [ ] Bitrate set to 10,000 Kbps
- [ ] Output format: MP4, H.264
- [ ] Audio input tested (clear, no background noise)
- [ ] Hotkeys configured (Start/Stop recording)

### Scene 1: The Problem (10-15 seconds)
- [ ] Terminal window captured
- [ ] Run Slither on demo contract
- [ ] Show overwhelming output (147 warnings)
- [ ] Scroll slowly through warnings
- [ ] Recorded 3 takes
- [ ] Best take selected
- [ ] File saved: `01_Raw_Footage/scene1_problem.mov`

### Scene 2: The Solution (10-15 seconds)
- [ ] Website opened (https://fboiero.github.io/MIESC/)
- [ ] Full screen mode
- [ ] Hero section visible
- [ ] Recorded smooth scroll
- [ ] Zoom into features section
- [ ] Recorded 2 takes
- [ ] File saved: `01_Raw_Footage/scene2_solution.mov`

### Scene 3: Setup (8-10 seconds)
- [ ] Claude Desktop config file opened
- [ ] Typed configuration (or smooth paste)
- [ ] File saved (Cmd+S visible)
- [ ] Claude Desktop restart shown
- [ ] Green "MIESC connected" indicator visible
- [ ] Recorded 3 takes
- [ ] File saved: `01_Raw_Footage/scene3_setup.mov`

### Scene 4: Live Demo (30-40 seconds)
- [ ] Split screen configured (Claude left, Terminal right)
- [ ] User prompt typed in Claude
- [ ] Background terminal shows tools running
  - [ ] `terminal_commands.sh` script used
  - [ ] Slither, Mythril, Aderyn outputs visible
  - [ ] AI filtering shown
- [ ] Claude response appears with findings
- [ ] Recorded 5 takes (this is the most important scene!)
- [ ] Best take with perfect timing selected
- [ ] File saved: `01_Raw_Footage/scene4_demo.mov`

### Scene 5: Before/After (8-10 seconds)
- [ ] `compare.html` opened in full screen
- [ ] Animations play smoothly
- [ ] Both columns visible
- [ ] Recorded 2 takes
- [ ] File saved: `01_Raw_Footage/scene5_comparison.mov`

### Scene 6: Call to Action (5 seconds)
- [ ] Website homepage recorded
- [ ] Badges visible (GitHub stars, tests passing, etc.)
- [ ] `logo_animation.html` recorded
- [ ] Smooth fade to black
- [ ] File saved: `01_Raw_Footage/scene6_cta.mov`

---

## 🎙️ AUDIO RECORDING

### Voiceover Setup
- [ ] Microphone tested (levels good, no clipping)
- [ ] Quiet room (no background noise)
- [ ] Audacity configured (48kHz, 32-bit)
- [ ] Script visible on screen
- [ ] Water available (stay hydrated!)

### Recording Session
- [ ] Warm-up (read through 5 times)
- [ ] Room tone recorded (30 seconds of silence)
- [ ] Full script recorded - Take 1
- [ ] Full script recorded - Take 2
- [ ] Full script recorded - Take 3
- [ ] Specific lines re-recorded (if needed)
- [ ] Raw file saved: `02_Audio/voiceover_raw.wav`

### Audio Post-Production
- [ ] Noise reduction applied (using room tone)
- [ ] Normalized to -1.0 dB
- [ ] Compression applied (3:1 ratio, -12dB threshold)
- [ ] EQ applied (optional, for clarity)
- [ ] Exported as MP3 320kbps
- [ ] File saved: `02_Audio/voiceover_edited.mp3`

### Music & SFX
- [ ] Music tracks downloaded:
  - [ ] Intro music (tense)
  - [ ] Main music (uplifting tech)
  - [ ] Outro music (triumphant)
- [ ] Sound effects downloaded:
  - [ ] Whoosh (transitions)
  - [ ] Typing sounds
  - [ ] Notification ding
  - [ ] Success sound
- [ ] All files in `02_Audio/sfx/` folder

---

## 🎨 GRAPHICS & ANIMATION

### Text Overlays Created
- [ ] Scene 1: "147 Warnings 😵"
- [ ] Scene 2: "MIESC - Multi-Agent Security Framework"
- [ ] Scene 3: "Setup in 30 seconds"
- [ ] Scene 4: "Claude Desktop" label
- [ ] Scene 4: "MIESC Tools Running" label
- [ ] Scene 5: "Before MIESC" / "With MIESC" titles
- [ ] Scene 6: "github.com/fboiero/MIESC"
- [ ] Scene 6: Metrics overlays:
  - [ ] "89.47% Precision"
  - [ ] "90% Time Saved"
  - [ ] "43% FP Reduction"
  - [ ] "15 Tools"

### Animation Elements
- [ ] Fade in/out transitions created
- [ ] Zoom effects configured
- [ ] Text animation keyframes set
- [ ] Lower thirds designed
- [ ] Call-out boxes/arrows ready
- [ ] Highlight effects ready

---

## ✂️ VIDEO EDITING

### DaVinci Resolve Project Setup
- [ ] New project created: "MIESC_Demo_90s"
- [ ] Timeline settings: 1920x1080, 60fps
- [ ] All media imported into Media Pool
- [ ] 3 audio tracks configured:
  - [ ] Track 1: Voiceover
  - [ ] Track 2: Music
  - [ ] Track 3: Sound effects

### Scene Assembly
- [ ] **Scene 1** (0-15s) assembled
  - [ ] Best footage selected and trimmed
  - [ ] Voiceover synced (0-10s)
  - [ ] Text overlay added
  - [ ] Zoom effect applied
  - [ ] Color grading applied (slight red tint)

- [ ] **Scene 2** (15-30s) assembled
  - [ ] Website footage trimmed
  - [ ] Voiceover synced (10-25s)
  - [ ] Text overlays added
  - [ ] Smooth zoom transition
  - [ ] Music starts (fade in)

- [ ] **Scene 3** (30-40s) assembled
  - [ ] Config footage (speed up typing 1.5x)
  - [ ] Voiceover synced (25-35s)
  - [ ] Callout arrows added
  - [ ] Checkmark animation on save

- [ ] **Scene 4** (40-75s) assembled
  - [ ] Split-screen footage
  - [ ] Voiceover synced (35-60s)
  - [ ] Labels added (Claude/Terminal)
  - [ ] Glow effects on key moments
  - [ ] Highlights on critical findings
  - [ ] Typing sound effects added
  - [ ] Music builds

- [ ] **Scene 5** (75-85s) assembled
  - [ ] Comparison graphic
  - [ ] Staggered line animations
  - [ ] Voiceover synced (60-70s)
  - [ ] Ding sounds on checkmarks

- [ ] **Scene 6** (85-90s) assembled
  - [ ] Website + logo animation
  - [ ] Voiceover synced (70-85s)
  - [ ] Text overlays with metrics
  - [ ] Music fades out
  - [ ] End card with logo

### Transitions
- [ ] Scene 1→2: Smooth cut + whoosh
- [ ] Scene 2→3: Cross dissolve (1s)
- [ ] Scene 3→4: Wipe transition
- [ ] Scene 4→5: Smooth cut
- [ ] Scene 5→6: Fade to/from black
- [ ] All transitions feel natural

### Audio Mixing
- [ ] Voiceover level: -3 dB
- [ ] Music level: -18 dB
- [ ] SFX level: -12 dB
- [ ] Ducking applied (music lowers when voice plays)
- [ ] No audio clipping
- [ ] Smooth fade in/out for music
- [ ] Test on headphones
- [ ] Test on laptop speakers

### Color Grading
- [ ] Color group created for all clips
- [ ] Lift adjusted: +0.1
- [ ] Gamma adjusted: +0.05
- [ ] Gain adjusted: +0.1
- [ ] Saturation: +10%
- [ ] Temperature: -5 (slightly cooler/blue)
- [ ] Consistent look across all scenes
- [ ] Preview on different displays

### Final Touches
- [ ] All text readable (test at 480p)
- [ ] Animations smooth (no stuttering)
- [ ] Audio perfectly synced
- [ ] No dead space/awkward pauses
- [ ] Pacing feels right (not too slow/fast)
- [ ] Opening is engaging
- [ ] Ending has clear CTA

---

## 📤 EXPORT & QUALITY CHECK

### Export Settings
- [ ] Format: MP4
- [ ] Codec: H.264
- [ ] Resolution: 1920x1080
- [ ] Frame Rate: 60 fps
- [ ] Bitrate: 10,000 Kbps (or Automatic)
- [ ] Audio: AAC, 320 kbps
- [ ] Filename: `MIESC_Demo_90s_Final.mp4`
- [ ] Location: `05_Export/`
- [ ] Render started
- [ ] ⏱️ Render completed (~5-10 minutes)

### Quality Check
- [ ] Video plays smoothly (no stuttering)
- [ ] Audio is clear and balanced
- [ ] No visual artifacts
- [ ] Text is readable
- [ ] Colors look good
- [ ] Transitions are smooth
- [ ] File size reasonable (<500MB)
- [ ] Duration is correct (85-95 seconds)

### Alternative Versions
- [ ] **30-second version** created (Twitter/Instagram)
  - [ ] Scenes 4 & 6 only
  - [ ] Demo sped up 1.5x
  - [ ] Exported: `MIESC_Demo_30s.mp4`

- [ ] **60-second version** created (LinkedIn)
  - [ ] Scenes 2, 4, 5, 6
  - [ ] Trimmed transitions
  - [ ] Exported: `MIESC_Demo_60s.mp4`

### Thumbnail Creation
- [ ] Frame exported from Scene 4 (live demo)
  OR
- [ ] Custom thumbnail created in Canva
  - [ ] Resolution: 1280x720
  - [ ] Bold text: "AI Security in 60 Seconds"
  - [ ] Subtext: "147 → 6 Findings"
  - [ ] Logo visible
  - [ ] High contrast colors
  - [ ] Readable on mobile
- [ ] Exported: `05_Export/thumbnail.png`

---

## 🚀 PUBLISHING

### YouTube Upload
- [ ] Video uploaded
- [ ] **Title**: "AI-Powered Smart Contract Security in 60 Seconds | MIESC + Claude Desktop Demo"
- [ ] **Description** complete with:
  - [ ] Project overview
  - [ ] Key metrics
  - [ ] Links (GitHub, docs, website)
  - [ ] Timestamps
  - [ ] Hashtags
- [ ] **Tags** added (15-20 tags)
- [ ] **Thumbnail** uploaded
- [ ] **Playlist** created/added to
- [ ] Visibility: Public
- [ ] **Published** ✅

### Captions/Subtitles
- [ ] Auto-captions reviewed
- [ ] Manual corrections made
- [ ] Uploaded to YouTube
- [ ] Tested (readable, accurate)

### Social Media Posts

**Twitter/X:**
- [ ] 30-second video uploaded
- [ ] Tweet written (280 chars)
- [ ] Hashtags included
- [ ] Link to full video
- [ ] Posted ✅

**LinkedIn:**
- [ ] 60-second video uploaded
- [ ] Professional post written
- [ ] Link to GitHub
- [ ] Posted ✅

**Reddit:**
- [ ] Posted to r/ethereum
- [ ] Posted to r/ethdev
- [ ] Posted to r/smartcontracts
- [ ] Posted to r/cybersecurity
- [ ] Demo contract code shared in comments

**Dev.to / Medium:**
- [ ] Blog post written
- [ ] Video embedded
- [ ] Code examples included
- [ ] Published ✅

### GitHub Updates
- [ ] Video linked in README.md
- [ ] Added to website
- [ ] Announcement issue created
- [ ] Shared in Discussions

---

## 📊 POST-LAUNCH

### Analytics Setup
- [ ] YouTube Analytics monitored
- [ ] Track views (first 24h, 7d, 30d)
- [ ] Track watch time
- [ ] Track CTR (Click-Through Rate)
- [ ] Monitor comments
- [ ] Respond to questions

### Engagement
- [ ] Reply to YouTube comments
- [ ] Reply to tweets
- [ ] Reply to Reddit comments
- [ ] Answer LinkedIn messages
- [ ] Track GitHub stars increase

### Performance Metrics (Track Weekly)
- [ ] Week 1:
  - [ ] Views: _______
  - [ ] Watch time: _______
  - [ ] GitHub stars: _______

- [ ] Week 2:
  - [ ] Views: _______
  - [ ] Watch time: _______
  - [ ] GitHub stars: _______

### Optimization (Based on Data)
- [ ] A/B test different thumbnails
- [ ] Adjust title if low CTR
- [ ] Pin best comment
- [ ] Create follow-up content if successful

---

## ✅ COMPLETION

- [ ] All checklist items completed
- [ ] Video performing well
- [ ] Community engagement positive
- [ ] Lessons learned documented

**Congratulations! 🎉 Your MIESC demo video is live!**

---

**Production Date:** ___________________
**Launch Date:** ___________________
**Team Members:** ___________________
**Total Time Spent:** ___________________

**Notes:**
_____________________________________________
_____________________________________________
_____________________________________________

# MIESC Video Demo Script
## "AI-Powered Smart Contract Security in 60 Seconds"

**Duration:** 90 seconds
**Target Audience:** Blockchain developers, security engineers, DeFi teams
**Goal:** Show MIESC's MCP integration with Claude Desktop for instant security analysis
**Tone:** Professional, confident, fast-paced

---

## 🎬 SCENE BREAKDOWN

### SCENE 1: The Problem (0-15 seconds)
**Visual:** Screen recording of terminal with overwhelming Slither output

**Voiceover:**
> "You just ran Slither on your smart contract. 147 warnings. 89 are informational. 37 are low priority. Which ones actually matter?"

**On-screen text:**
- `slither MyToken.sol` → 147 findings
- Developer frustrated face emoji 😵
- "Hours wasted triaging false positives"

**Music:** Tense, rising tension

---

### SCENE 2: The Solution (15-30 seconds)
**Visual:** Claude Desktop interface appears, clean and modern

**Voiceover:**
> "Meet MIESC. A Model Context Protocol server that brings 15 security tools directly into Claude Desktop. Just ask Claude to audit your contract."

**On-screen text:**
- "MIESC = Multi-Agent Security Framework"
- "15 tools: Slither, Mythril, Echidna, Aderyn..."
- "Powered by MCP (Model Context Protocol)"

**Visual Transition:** Smooth zoom into Claude Desktop window

**Music:** Shift to uplifting, confident

---

### SCENE 3: Live Demo - Setup (30-40 seconds)
**Visual:** Screen recording showing Claude Desktop configuration

**Voiceover:**
> "Setup takes 30 seconds. Add MIESC to your Claude Desktop config..."

**On-screen steps (animated):**
```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/MIESC/src/mcp/server.py"]
    }
  }
}
```

**Voiceover continues:**
> "...restart Claude. Done."

**Visual:** Checkmark ✅ animation

---

### SCENE 4: Live Demo - The Magic (40-75 seconds)
**Visual:** Claude Desktop conversation window

**User types in Claude:**
> "Audit this DeFi lending contract for me. Focus on critical vulnerabilities."

**Claude responds (animated typing):**
> "I'll use MIESC to run a comprehensive security audit. Let me check..."

**Visual:** Behind-the-scenes split screen showing:
- **Left:** Claude Desktop conversation
- **Right:** Terminal showing MIESC tools running in real-time:
  - `[Slither] Running 87 detectors...` ⚡
  - `[Mythril] Symbolic execution...` 🔍
  - `[Aderyn] AST analysis...` 🦀
  - `[AIAgent] Filtering false positives...` 🤖

**Claude's response appears:**
> "✅ **Analysis Complete**
>
> **CRITICAL (1):** Reentrancy vulnerability in `withdraw()` function
> - Line 47: External call before state update
> - Exploitable via recursive callback
> - Fix: Use Checks-Effects-Interactions pattern
>
> **HIGH (2):** Missing access control on `setPrice()`
> **MEDIUM (3):** Unchecked return values
>
> **139 false positives filtered by AI**
>
> Would you like me to generate a patch for the reentrancy issue?"

**On-screen highlights:**
- Real vulnerabilities: 🔴 Highlighted
- False positives filtered: ❌ Crossed out
- Confidence score: 89.47%

**Music:** Building momentum

---

### SCENE 5: The Results (75-85 seconds)
**Visual:** Side-by-side comparison animation

**Left side (Traditional):**
- ❌ Run 5+ tools manually
- ❌ 147 warnings
- ❌ Hours of manual triage
- ❌ Miss critical issues in noise

**Right side (MIESC + Claude):**
- ✅ One conversation
- ✅ 6 real vulnerabilities
- ✅ AI-filtered results
- ✅ Actionable fixes

**Voiceover:**
> "From 147 warnings to 6 actionable findings. From hours to minutes. That's the power of AI-assisted security."

---

### SCENE 6: Call to Action (85-90 seconds)
**Visual:** MIESC website with animated gradient background

**Text on screen (animated fade-in):**
```
MIESC
Multi-Agent Security Framework
for Smart Contracts

✨ 15 security tools
🤖 AI-powered triage
🎯 89.47% precision
⚡ 90% time saved

Open Source • GPL-3.0
```

**Voiceover:**
> "MIESC. Open source. Battle-tested on 5,000+ contracts. Available now on GitHub."

**On-screen buttons:**
- 🌐 **fboiero.github.io/MIESC**
- 💻 **github.com/fboiero/MIESC**
- 📖 **Read the Docs**

**End screen:** Logo animation with tagline:
> **"Defense-in-Depth for the Decentralized World"**

**Music:** Triumphant finish

---

## 📋 PRODUCTION NOTES

### Recording Requirements

**Software:**
- **Screen Recording:** OBS Studio (free) or ScreenFlow (paid)
- **Video Editing:** DaVinci Resolve (free) or Final Cut Pro
- **Voice Recording:** Audacity (free) or Adobe Audition
- **Animation:** After Effects or Motion (for text overlays)

**Screen Resolution:**
- Record at 1920x1080 (1080p) minimum
- Use 16:9 aspect ratio
- 60fps for smooth terminal animations

### Pre-recording Checklist

**1. Environment Setup:**
- [ ] Clean desktop (hide personal files)
- [ ] Use a professional wallpaper (dark theme)
- [ ] Close unnecessary applications
- [ ] Disable notifications (macOS: Do Not Disturb)
- [ ] Set terminal to readable font size (14-16pt)
- [ ] Use a clean terminal theme (e.g., Dracula, Nord)

**2. MIESC Configuration:**
- [ ] Test MCP server connection
- [ ] Prepare vulnerable contract (`VulnerableBank.sol`)
- [ ] Run test audit to verify tools work
- [ ] Clear previous outputs
- [ ] Have example ready to run

**3. Claude Desktop Setup:**
- [ ] Clear conversation history (fresh start)
- [ ] Test MCP connection (check green status)
- [ ] Prepare prompt in text file (for copy-paste)
- [ ] Set window size for recording

**4. Audio:**
- [ ] Record in quiet room (no background noise)
- [ ] Use quality microphone (USB mic or headset)
- [ ] Record voiceover separately (easier to edit)
- [ ] Test audio levels (no clipping, no distortion)

### Shooting Tips

**1. Screen Recording:**
- Record in multiple takes (easier to edit)
- Use zoom-in effects on important text
- Slow down typing for readability (0.7x speed)
- Use callouts/arrows to highlight key points

**2. Terminal Commands:**
- Type commands slowly and deliberately
- Add small delays between commands
- Use clear, readable prompts
- Highlight important output lines

**3. Claude Conversation:**
- Use realistic typing speed (not instant)
- Add "Claude is thinking..." indicator
- Show tools running in background (split screen)
- Highlight key parts of response

**4. Transitions:**
- Use smooth fades (0.5-1 second)
- Add whoosh sounds for quick cuts
- Use zoom effects for emphasis
- Maintain consistent pacing

### Post-Production

**1. Video Editing:**
- Cut dead space (silence, waiting)
- Add text overlays with key points
- Use split-screen for before/after
- Add subtle zoom effects on important parts
- Color grade for consistency (dark cybersecurity theme)

**2. Audio Editing:**
- Remove background noise
- Normalize volume levels
- Add music (royalty-free from Epidemic Sound, Artlist)
- Add sound effects (typing, whoosh, notification)
- Mix voiceover + music (voice at -3dB, music at -18dB)

**3. Graphics:**
- Add animated text overlays
- Use consistent font (Inter or Poppins)
- Add logos and badges
- Create smooth transitions
- Export at 1080p, 60fps, H.264

### Music Recommendations (Royalty-Free)

**Intro (Tense):**
- "Tension Rising" - Epidemic Sound
- "Dark Countdown" - Artlist

**Main (Uplifting/Tech):**
- "Digital Innovation" - Epidemic Sound
- "Tech Atmosphere" - Artlist
- "Futuristic Beat" - YouTube Audio Library

**Outro (Triumphant):**
- "Epic Victory" - Epidemic Sound
- "Success Theme" - Artlist

---

## 🎯 ALTERNATIVE VERSIONS

### 30-Second Version (Twitter/LinkedIn)
Focus on Scene 4 only:
- Show Claude conversation
- Show instant results
- End with CTA

### 2-Minute Extended Version (YouTube)
Add these scenes:
- **Scene 2.5:** Show all 15 tools in action (10s)
- **Scene 4.5:** Show patch generation (15s)
- **Scene 5.5:** Show compliance report (10s)
- **Scene 6.5:** Testimonials/metrics (15s)

### 5-Minute Tutorial Version (Documentation)
Full walkthrough:
- Installation (1 min)
- Configuration (1 min)
- First audit (2 min)
- Advanced features (1 min)

---

## 📝 VOICEOVER SCRIPT (Full Text)

**[INTRO - 0:00-0:15]**
You just ran Slither on your smart contract. 147 warnings. 89 are informational. 37 are low priority. Which ones actually matter?

**[SOLUTION - 0:15-0:30]**
Meet MIESC. A Model Context Protocol server that brings 15 security tools directly into Claude Desktop. Just ask Claude to audit your contract.

**[SETUP - 0:30-0:40]**
Setup takes 30 seconds. Add MIESC to your Claude Desktop config, restart Claude. Done.

**[DEMO - 0:40-0:75]**
Watch. I ask Claude to audit this DeFi lending contract. Behind the scenes, MIESC orchestrates Slither, Mythril, Aderyn, and 12 other tools. AI filters the noise. Claude gives me 6 actionable findings, ranked by severity, with fix suggestions.

**[RESULTS - 0:75-0:85]**
From 147 warnings to 6 actionable findings. From hours to minutes. That's the power of AI-assisted security.

**[CTA - 0:85-0:90]**
MIESC. Open source. Battle-tested on 5,000+ contracts. Available now on GitHub.

---

## 🎬 EXAMPLE VULNERABLE CONTRACT

Create this file for the demo: `examples/demo_vulnerable.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank - Demo contract with intentional vulnerabilities
/// @notice DO NOT USE IN PRODUCTION - For educational purposes only
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Deposit ETH into the bank
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    /// @notice Withdraw ETH - VULNERABLE TO REENTRANCY!
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // CRITICAL: External call before state update (SWC-107)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // ❌ Too late! Reentrancy possible
    }

    /// @notice Update user balance - HIGH: Missing access control!
    function setBalance(address user, uint256 amount) public {
        // HIGH: Anyone can call this! No onlyOwner modifier
        balances[user] = amount;
    }

    /// @notice Get contract balance - MEDIUM: Unchecked return value
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Emergency withdraw - HIGH: Unsafe transfer
    function emergencyWithdraw(address payable recipient) public {
        require(msg.sender == owner, "Not owner");
        // MEDIUM: No checks on recipient (could be contract)
        recipient.transfer(address(this).balance);
    }
}

// Expected MIESC Findings:
// 🔴 CRITICAL (1): Reentrancy in withdraw() - Line 23
// 🟠 HIGH (2): Missing access control on setBalance() - Line 31
// 🟠 HIGH (2): Unsafe transfer in emergencyWithdraw() - Line 43
// 🟡 MEDIUM (3): No check on recipient address
// 🟢 LOW (5): Missing events for state changes
// ℹ️  INFO (20): Gas optimizations, naming conventions
```

---

## 🎥 STORYBOARD VISUAL GUIDE

```
┌─────────────────────────────────────────────────────────────┐
│ SCENE 1: Problem                                            │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ $ slither MyToken.sol                                   │ │
│ │ ⚠️  147 findings detected                                │ │
│ │ 😵 "Which ones matter?"                                  │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCENE 2: Solution                                           │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │      🛡️ MIESC                                            │ │
│ │      Multi-Agent Security Framework                     │ │
│ │      + Claude Desktop (MCP)                             │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCENE 3: Setup                                              │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ claude_desktop_config.json                              │ │
│ │ {                                                        │ │
│ │   "mcpServers": {                                       │ │
│ │     "miesc": {...}  ← Add this                          │ │
│ │   }                                                      │ │
│ │ }                                                        │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCENE 4: Live Demo                                          │
│ ┌──────────────────────┬──────────────────────────────────┐ │
│ │ Claude Desktop       │ Terminal (Background)            │ │
│ │                      │                                  │ │
│ │ User: Audit this     │ [Slither] Running... ⚡           │ │
│ │ contract            │ [Mythril] Analyzing... 🔍         │ │
│ │                      │ [Aderyn] Scanning... 🦀           │ │
│ │ Claude: ✅ Found:    │ [AIAgent] Filtering... 🤖         │ │
│ │ 🔴 1 CRITICAL        │                                  │ │
│ │ 🟠 2 HIGH            │ ✅ Complete!                      │ │
│ │ 🟡 3 MEDIUM          │                                  │ │
│ └──────────────────────┴──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCENE 5: Before/After                                       │
│ ┌──────────────────────┬──────────────────────────────────┐ │
│ │ Before MIESC         │ With MIESC                       │ │
│ │ ❌ 147 warnings      │ ✅ 6 real issues                 │ │
│ │ ❌ Hours of work     │ ✅ Minutes                       │ │
│ │ ❌ Miss criticals    │ ✅ AI-ranked                     │ │
│ └──────────────────────┴──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SCENE 6: CTA                                                │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │              🛡️ MIESC                                    │ │
│ │     github.com/fboiero/MIESC                            │ │
│ │                                                          │ │
│ │  ✨ Open Source  🎯 89.47% Precision  ⚡ 90% Faster      │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 METRICS TO HIGHLIGHT

Use these compelling statistics in overlays:

- **89.47%** Precision (9/10 findings are real)
- **86.2%** Recall (catches 86% of vulnerabilities)
- **43%** False Positive Reduction
- **90%** Time Saved (32-50h → 3-5h)
- **15** Security Tools Integrated
- **5,127** Contracts Tested
- **12** Compliance Standards
- **0.847** Cohen's Kappa (expert agreement)

---

## 🚀 DISTRIBUTION PLAN

### YouTube
- **Title:** "AI-Powered Smart Contract Security with Claude Desktop + MIESC"
- **Description:** Full product description + links
- **Tags:** smart contracts, security, AI, Claude, MCP, blockchain, solidity
- **Thumbnail:** Professional with "90% Faster" text

### Twitter/X
- 30-second version
- Thread with behind-the-scenes
- Pin tweet with link

### LinkedIn
- 60-second version
- Professional caption about security automation
- Tag relevant companies (Trail of Bits, OpenZeppelin, etc.)

### Reddit
- r/ethereum, r/ethdev, r/smartcontracts
- r/cybersecurity, r/netsec
- Include demo contract in comments

### Dev.to / Medium
- Write accompanying blog post
- Embed video
- Include code examples

---

## ✅ FINAL CHECKLIST

Before publishing:
- [ ] Test all demo commands work
- [ ] Verify MCP connection is stable
- [ ] Proofread all text overlays
- [ ] Check audio levels (no clipping)
- [ ] Verify video quality (1080p minimum)
- [ ] Add captions/subtitles (accessibility)
- [ ] Test on mobile devices
- [ ] Create eye-catching thumbnail
- [ ] Prepare social media posts
- [ ] Set up tracking links (UTM parameters)

---

**Last Updated:** December 2024
**Author:** Fernando Boiero
**License:** GPL-3.0 (MIESC Project)

# MIESC Web Demo Screenshots

This directory contains screenshots of the MIESC web demo interface.

## Screenshots Needed

### 1. Main Interface (`main_interface.png`)
- Full web demo homepage
- Shows input section and sidebar configuration
- Resolution: 1920x1080

### 2. Analysis in Progress (`analysis_progress.png`)
- Progress bar showing multi-phase analysis
- Real-time status updates
- Resolution: 1920x1080

### 3. Results Dashboard (`results_dashboard.png`)
- Summary metrics cards
- Severity distribution chart
- Findings list
- Resolution: 1920x1080

### 4. Detailed Finding (`detailed_finding.png`)
- Expanded finding card
- AI analysis section
- Risk scores and policy mappings
- Resolution: 1920x600

### 5. Export Options (`export_options.png`)
- JSON and Markdown export buttons
- Download dialogs
- Resolution: 1920x400

## How to Generate Screenshots

### Option 1: Manual Screenshots

```bash
# Launch the webapp
make webapp

# Navigate to http://localhost:8501

# Use browser screenshot tools:
# - Chrome: Ctrl+Shift+P → "Capture full size screenshot"
# - Firefox: Ctrl+Shift+S → Select area
# - macOS: Cmd+Shift+4 → Select area

# Save screenshots to this directory
```

### Option 2: Automated Screenshots (Playwright)

```bash
# Install Playwright
pip install playwright
playwright install chromium

# Run screenshot script
python scripts/generate_webapp_screenshots.py
```

## Usage in Documentation

Screenshots are referenced in:
- `README.md` - Main repo overview
- `webapp/README.md` - Webapp documentation
- `docs/03_DEMO_GUIDE.md` - Demo guide
- Documentation site (MkDocs)

## Placeholder Images

Until real screenshots are captured, use placeholder images:

```markdown
![MIESC Web Demo](https://via.placeholder.com/1920x1080.png?text=MIESC+Web+Demo)
```

---

**Note**: Screenshots should be captured after every major UI update to keep documentation current.

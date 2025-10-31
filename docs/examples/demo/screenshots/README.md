# Demo Screenshots

This directory contains visual aids for the MIESC demo.

## Screenshots

### demo_results.png
Visual representation of MIESC analysis results showing:
- Vulnerability distribution by severity
- Tool comparison matrix
- AI correlation confidence scores

**Status:** Placeholder - Generate after running demo

### mcp_response.png
Screenshot of MCP REST API response in terminal showing:
- JSON-formatted capabilities endpoint response
- Metrics endpoint with precision/recall/F1 scores
- Audit endpoint request/response cycle

**Status:** Placeholder - Capture after `curl` commands

### coverage_badge.png
Test coverage badge showing 87.5% code coverage

**Status:** Placeholder - Generate from pytest-cov HTML report

---

## How to Generate Screenshots

### 1. Analysis Results Visualization

```bash
# Run demo
bash demo/run_demo.sh

# View results in browser (requires matplotlib/seaborn)
python3 -c "
import json
import matplotlib.pyplot as plt

with open('demo/expected_outputs/demo_report.json') as f:
    data = json.load(f)

# Create visualization
# ... plotting code ...
plt.savefig('demo/screenshots/demo_results.png')
"
```

### 2. MCP Response Screenshot

```bash
# Start MCP server
python3 src/miesc_mcp_rest.py &

# Capture curl output
curl http://localhost:5001/mcp/get_metrics | jq > temp.json

# Take screenshot of terminal
# (Use system screenshot tool: Cmd+Shift+4 on macOS, PrtScn on Linux)
```

### 3. Coverage Badge

```bash
# Generate HTML coverage report
pytest --cov=src --cov-report=html

# Open htmlcov/index.html in browser
# Screenshot the coverage percentage badge
```

---

**Note:** Screenshots are optional for the demo to function.
They enhance documentation but are not required for execution.

# 🎯 MIESC Agent Orchestration Demo

Interactive demonstration of multi-agent synchronized orchestration with visual feedback.

---

## 🚀 Quick Start

```bash
# Run the orchestration demo
python demo/orchestration_demo.py examples/reentrancy_simple.sol

# Export results to JSON
python demo/orchestration_demo.py examples/dao_vulnerable.sol --export results.json

# Help
python demo/orchestration_demo.py --help
```

---

## ✨ Features

- **17 Specialized Agents** orchestrated across 6 defense layers
- **Real-time Visual Feedback** with colored terminal output
- **Parallel Execution** for optimal performance
- **MCP Integration** for agent communication
- **JSON Export** of results
- **Progress Tracking** for each phase

---

## 📊 What You'll See

The demo shows:

1. **Phase 1:** Coordination & Planning (CoordinatorAgent)
2. **Phase 2:** Static Analysis (Slither, Aderyn, Wake)
3. **Phase 3:** Dynamic & Symbolic Execution
4. **Phase 4:** Formal Verification
5. **Phase 5:** AI-Powered Correlation & Triage
6. **Phase 6:** Policy & Compliance Validation

Each agent displays:
- Agent name with icon
- Agent type and speed
- Capabilities
- Execution time
- Findings count
- Real-time status

---

## 📁 Files

- **`orchestration_demo.py`** - Main orchestration script
- **`ORCHESTRATION_README.md`** - This file
- **`../docs/AGENT_ORCHESTRATION_GUIDE.md`** - Complete documentation

---

## 🎓 Academic Use

Perfect for:
- Thesis demonstrations
- Conference presentations
- Academic papers
- Teaching multi-agent systems
- Research validation

---

## 📚 More Information

See the complete guide: [AGENT_ORCHESTRATION_GUIDE.md](../docs/AGENT_ORCHESTRATION_GUIDE.md)

---

**Author:** Fernando Boiero
**Institution:** UNDEF - IUA Córdoba
**Version:** 3.3.0

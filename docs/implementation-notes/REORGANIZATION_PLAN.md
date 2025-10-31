# 📁 Repository Reorganization Plan

## Current Problems
- 30+ markdown files in root directory
- Multiple scripts scattered (demo.sh, demo_agents.sh, etc.)
- Python entry points mixed in root (main.py, main_ai.py, etc.)
- Multiple Dockerfiles and docker-compose files
- Hard to find important files (README, LICENSE, etc.)

## Proposed Structure

```
/
├── README.md                          # ✅ Keep (main entry point)
├── LICENSE                            # ✅ Keep (required)
├── SECURITY.md                        # ✅ Keep (GitHub security)
├── CONTRIBUTING.md                    # ✅ Keep (GitHub contributing)
├── requirements.txt                   # ✅ Keep (main dependencies)
├── requirements_*.txt                 # ✅ Keep (dependency variants)
├── foundry.toml                       # ✅ Keep (Foundry config)
├── xaudit.py                          # ✅ Keep (main CLI entry point)
│
├── docs/                              # 📚 ALL documentation
│   ├── README.md                      # Index of all docs
│   │
│   ├── setup/                         # Installation & setup guides
│   │   ├── QUICK_START.md
│   │   ├── INSTALL_SIMPLE.md
│   │   ├── EMPEZAR_AQUI.md
│   │   └── CONFIGURAR_REPO_GITHUB.md
│   │
│   ├── guides/                        # User guides
│   │   ├── DEMO_GUIDE.md
│   │   ├── AGENTS_VISUAL_GUIDE.md
│   │   ├── DEMO_EXECUTIVE_SUMMARY.md
│   │   ├── PRESENTATION_DEMO_READY.md
│   │   ├── QUICK_REFERENCE_MULTI_CONTRACT.md
│   │   └── LISTO_PARA_PROMOCIONAR.md
│   │
│   ├── architecture/                  # Technical architecture
│   │   ├── AGENT_PROTOCOL_WHITEPAPER.md
│   │   ├── README_AGENT_PROTOCOL.md
│   │   ├── AGENT_PROTOCOL_QUICKSTART.md
│   │   ├── IMPLEMENTATION_COMPLETE.md
│   │   ├── IMPLEMENTACION_COMPLETA.md
│   │   ├── IMPLEMENTACION_MULTI_CONTRATO.md
│   │   └── AGENT_ORCHESTRATOR_IMPLEMENTATION_COMPLETE.md
│   │
│   ├── compliance/                    # Standards & compliance
│   │   ├── COMPLIANCE.md
│   │   └── REFERENCES.md
│   │
│   ├── releases/                      # Release notes
│   │   └── WHATS_NEW_V2.2.md
│   │
│   ├── website/                       # Website development docs
│   │   ├── WEBSITE_IMPROVEMENTS.md
│   │   ├── FORMULARIO_DEMO_OPCIONES.md
│   │   └── GITHUB_REPO_CONFIG.md
│   │
│   └── internal/                      # Development sessions & notes
│       ├── SESSION_COMPLETE_SUMMARY.md
│       ├── SESSION_SUMMARY.md
│       └── RESUMEN_FINAL.txt
│
├── scripts/                           # ✅ Already exists - consolidate
│   ├── demos/
│   │   ├── demo.sh
│   │   ├── demo_agents.sh
│   │   ├── demo_complete.sh
│   │   ├── demo_presentation.sh
│   │   └── test_demo.sh
│   │
│   ├── analysis/
│   │   ├── generate_reports.py
│   │   ├── main.py
│   │   ├── main_ai.py
│   │   └── main_project.py
│   │
│   └── README.md                      # Scripts documentation
│
├── docker/                            # 🐳 Docker files
│   ├── Dockerfile
│   ├── Dockerfile.optimized
│   ├── docker-compose.yml
│   ├── docker-compose.optimized.yml
│   └── README.md                      # Docker setup guide
│
├── src/                               # ✅ Keep (source code)
├── tests/                             # ✅ Keep (test suite)
├── examples/                          # ✅ Keep (example contracts)
├── vulnerable_contracts/              # ✅ Keep (test contracts)
├── standards/                         # ✅ Keep (compliance standards)
├── config/                            # ✅ Keep (config files)
├── data/                              # ✅ Keep (data files)
├── analysis/                          # ✅ Keep (analysis results)
├── output/                            # ✅ Keep (output files)
├── outputs/                           # ⚠️  Merge with output/ or clarify
│
├── website/                           # 🌐 GitHub Pages website
│   ├── index.html
│   ├── pages/
│   ├── css/
│   ├── js/
│   └── assets/
│
├── thesis/                            # ✅ Keep (research materials)
├── video_assets/                      # ✅ Keep (presentation assets)
├── k8s/                               # ✅ Keep (Kubernetes configs)
│
└── venv/                              # ⚠️  .gitignore (not tracked)
```

## Migration Steps

### Phase 1: Create new directory structure
```bash
mkdir -p docs/{setup,guides,architecture,compliance,releases,website,internal}
mkdir -p scripts/{demos,analysis}
mkdir -p docker
mkdir -p website
```

### Phase 2: Move documentation files
```bash
# Setup guides
mv QUICK_START.md docs/setup/
mv INSTALL_SIMPLE.md docs/setup/
mv EMPEZAR_AQUI.md docs/setup/
mv CONFIGURAR_REPO_GITHUB.md docs/setup/

# User guides
mv DEMO_GUIDE.md docs/guides/
mv AGENTS_VISUAL_GUIDE.md docs/guides/
mv DEMO_EXECUTIVE_SUMMARY.md docs/guides/
mv PRESENTATION_DEMO_READY.md docs/guides/
mv QUICK_REFERENCE_MULTI_CONTRACT.md docs/guides/
mv LISTO_PARA_PROMOCIONAR.md docs/guides/

# Architecture
mv AGENT_PROTOCOL_WHITEPAPER.md docs/architecture/
mv README_AGENT_PROTOCOL.md docs/architecture/
mv AGENT_PROTOCOL_QUICKSTART.md docs/architecture/
mv IMPLEMENTATION_COMPLETE.md docs/architecture/
mv IMPLEMENTACION_COMPLETA.md docs/architecture/
mv IMPLEMENTACION_MULTI_CONTRATO.md docs/architecture/
mv AGENT_ORCHESTRATOR_IMPLEMENTATION_COMPLETE.md docs/architecture/

# Compliance
mv COMPLIANCE.md docs/compliance/
mv REFERENCES.md docs/compliance/

# Releases
mv WHATS_NEW_V2.2.md docs/releases/

# Website
mv WEBSITE_IMPROVEMENTS.md docs/website/
mv FORMULARIO_DEMO_OPCIONES.md docs/website/
mv GITHUB_REPO_CONFIG.md docs/website/

# Internal
mv SESSION_COMPLETE_SUMMARY.md docs/internal/
mv SESSION_SUMMARY.md docs/internal/
mv RESUMEN_FINAL.txt docs/internal/
```

### Phase 3: Move scripts
```bash
# Demo scripts
mv demo.sh scripts/demos/
mv demo_agents.sh scripts/demos/
mv demo_complete.sh scripts/demos/
mv demo_presentation.sh scripts/demos/
mv test_demo.sh scripts/demos/

# Analysis scripts
mv generate_reports.py scripts/analysis/
mv main.py scripts/analysis/
mv main_ai.py scripts/analysis/
mv main_project.py scripts/analysis/
```

### Phase 4: Move Docker files
```bash
mv Dockerfile docker/
mv Dockerfile.optimized docker/
mv docker-compose.yml docker/
mv docker-compose.optimized.yml docker/
```

### Phase 5: Move website files
```bash
mv index.html website/
mv pages/ website/
mv css/ website/
mv js/ website/
```

### Phase 6: Update references
- Update paths in README.md
- Update imports in Python files
- Update script paths
- Update GitHub Pages config (if needed)
- Update CI/CD configs

### Phase 7: Test everything
- Run regression tests
- Test all demo scripts
- Test Docker builds
- Verify GitHub Pages still works

## Files to Keep in Root

**Essential files only:**
- README.md (main project entry)
- LICENSE (legal requirement)
- SECURITY.md (GitHub security policy)
- CONTRIBUTING.md (GitHub contributing guide)
- requirements.txt (Python dependencies)
- requirements_*.txt (dependency variants)
- foundry.toml (Foundry config)
- xaudit.py (CLI entry point)
- .gitignore
- .github/ (GitHub workflows)

## Benefits

✅ **Cleaner root** - Only essential files visible
✅ **Better navigation** - Logical folder structure
✅ **Easier onboarding** - Clear documentation hierarchy
✅ **Professional appearance** - Standard project structure
✅ **Maintainability** - Easier to find and update files
✅ **Scalability** - Room for growth without clutter

## Backwards Compatibility

- Keep symbolic links for frequently accessed docs (optional)
- Update all documentation links
- Add redirect notices in old locations (if needed)
- Update CI/CD and automation scripts

# CLAUDE.md - Project Instructions for Claude Code

## Project: MIESC
Multi-layer Intelligent Evaluation for Smart Contracts

## Git Commit Rules

- **Author**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
- **NO Co-Authors**: Do NOT add "Co-Authored-By" lines to commits. Fernando is the sole author of all contributions to this project.

## Commit Message Style

Use conventional commits format:
- `feat(scope):` New features
- `fix(scope):` Bug fixes
- `chore(scope):` Maintenance tasks
- `docs(scope):` Documentation updates
- `refactor(scope):` Code refactoring

## Language Preferences

- Code comments: English
- User interaction: Spanish preferred when user writes in Spanish
- Commit messages: English

## Project Structure

- `miesc/cli/main.py` - Main CLI entry point
- `src/` - Core source code
- `src/adapters/` - Tool adapters for security analysis
- `src/reports/` - Report generation modules
- `src/llm/` - LLM integration helpers
- `config/miesc.yaml` - Central configuration
- `docs/templates/reports/` - Report templates

## Docker

- Use `docker-compose.yml` for local development
- Ollama integration available via `--profile llm`

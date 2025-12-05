# MIESC Governance

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

*Version 1.0 - December 2024*

---

## Overview

This document describes the governance structure for the MIESC project, including decision-making processes, roles and responsibilities, and community participation guidelines.

---

## Project Structure

### Current Status

MIESC is currently in its **initial development phase** as part of a Master's thesis at Universidad de la Defensa Nacional (UNDEF), Argentina. The project is transitioning toward a **community-driven open-source model**.

### Governance Model

**Benevolent Dictator For Now (BDFN)** → **Meritocratic Governance** (planned)

| Phase | Model | Timeline |
|-------|-------|----------|
| Current | Single maintainer (thesis phase) | Through Q4 2025 |
| Transition | Core team formation | 2026 |
| Future | Meritocratic with elected steering committee | 2027+ |

---

## Roles and Responsibilities

### Project Lead / Maintainer

**Current**: Fernando Boiero

**Responsibilities**:
- Strategic direction and roadmap
- Final decision authority on major changes
- Release management
- Community health and code of conduct enforcement
- External communications and partnerships

### Contributors

Anyone who contributes to MIESC through:
- Code contributions (pull requests)
- Documentation improvements
- Bug reports and issue triage
- Community support and user assistance
- Translations
- Testing and quality assurance

**Recognition**: All contributors are acknowledged in [CONTRIBUTORS.md](./CONTRIBUTORS.md).

### Core Team (Future)

As the project grows, a core team will be established with:
- Commit access to the main repository
- Participation in release decisions
- Mentorship of new contributors

**Selection criteria**:
- Sustained, quality contributions
- Demonstrated understanding of project goals
- Positive community interactions
- Commitment to project values

---

## Decision Making

### Types of Decisions

| Decision Type | Process | Approval |
|---------------|---------|----------|
| Bug fixes | Pull request review | Maintainer approval |
| Minor features | Pull request + discussion | Maintainer approval |
| Major features | RFC process | Community + maintainer |
| Breaking changes | RFC + deprecation period | Consensus |
| Governance changes | RFC + vote | Supermajority (2/3) |

### RFC (Request for Comments) Process

Major changes follow an RFC process:

1. **Draft**: Author creates RFC in `rfcs/` directory
2. **Discussion**: Minimum 2-week community discussion period
3. **Revision**: Author addresses feedback
4. **Decision**: Maintainer makes final call (or community vote for governance)
5. **Implementation**: Approved RFCs are implemented

**RFC Template**: [rfcs/0000-template.md](./rfcs/0000-template.md)

### Consensus Seeking

We aim for rough consensus on most decisions:
- Listen to all perspectives
- Address concerns constructively
- Seek solutions that work for everyone
- Maintainer breaks ties when consensus isn't reached

---

## Community Participation

### Communication Channels

| Channel | Purpose | Link |
|---------|---------|------|
| GitHub Issues | Bug reports, feature requests | [Issues](https://github.com/fboiero/MIESC/issues) |
| GitHub Discussions | General questions, ideas | [Discussions](https://github.com/fboiero/MIESC/discussions) |
| Pull Requests | Code contributions | [PRs](https://github.com/fboiero/MIESC/pulls) |
| Email | Private matters | fboiero@frvm.utn.edu.ar |

### Contribution Guidelines

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed contribution guidelines.

**Quick summary**:
1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request
5. Respond to review feedback

### Code Review

All code changes require review:
- At least one approval from a maintainer
- CI checks must pass
- Documentation updated if applicable
- Tests included for new features

---

## Release Process

### Versioning

MIESC follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Schedule

| Release Type | Frequency | Example |
|--------------|-----------|---------|
| Patch | As needed | 4.0.1, 4.0.2 |
| Minor | Monthly-Quarterly | 4.1.0, 4.2.0 |
| Major | Annually | 5.0.0 |

### Release Checklist

1. All tests passing
2. Documentation updated
3. CHANGELOG.md updated
4. Version bumped in pyproject.toml
5. Release notes drafted
6. Git tag created
7. GitHub release published
8. Announcement posted

---

## Conflict Resolution

### Technical Disagreements

1. Discuss in the relevant issue/PR
2. Seek additional perspectives
3. Maintainer makes final decision
4. Decision is documented

### Interpersonal Conflicts

1. Refer to [Code of Conduct](./CODE_OF_CONDUCT.md)
2. Report to maintainer: fboiero@frvm.utn.edu.ar
3. Maintainer investigates privately
4. Appropriate action taken

### Appeals

Decisions can be appealed by:
1. Opening a GitHub Discussion
2. Presenting new information
3. Community discussion (2 weeks)
4. Final decision by maintainer/steering committee

---

## Sustainability

### Funding

Current status: Unfunded academic project

**Planned funding sources**:
- [ ] Digital Public Goods Alliance pathfinder grants
- [ ] Academic research grants
- [ ] GitHub Sponsors
- [ ] Foundation support

### Resource Allocation

When funding is available, priorities:
1. Infrastructure (CI/CD, hosting)
2. Security audits
3. Community events
4. Contributor stipends

### Succession Planning

To ensure project continuity:
- Documentation of all processes
- Multiple maintainers (future)
- Open governance model
- Institutional partnerships

---

## Amendments

This governance document can be amended through:

1. RFC proposing changes
2. 4-week discussion period
3. 2/3 majority approval (when applicable)
4. Maintainer approval during initial phase

---

## Related Documents

- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) - Community standards
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](./SECURITY.md) - Security policy
- [PRIVACY.md](./PRIVACY.md) - Privacy policy
- [DPG-COMPLIANCE.md](./DPG-COMPLIANCE.md) - Digital Public Good compliance

---

## Contact

**Project Lead**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institution**: Universidad de la Defensa Nacional (UNDEF), Argentina

---

*This governance model is inspired by established open-source projects including Apache, Rust, and Python.*

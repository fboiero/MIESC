# MIESC Governance

This document describes the governance model for the MIESC project.

---

## Overview

MIESC is an open source project governed by a transparent decision-making process. We aim to build a welcoming community where contributors can grow into maintainers and help shape the project's future.

---

## Roles and Responsibilities

### Users

Anyone who uses MIESC. Users are encouraged to:

- Report bugs and request features via [GitHub Issues](https://github.com/fboiero/MIESC/issues)
- Participate in [GitHub Discussions](https://github.com/fboiero/MIESC/discussions)
- Help other users in the community

### Contributors

Anyone who contributes to the project. Contributions include:

- Code (bug fixes, features, documentation)
- Issue triage and support
- Documentation improvements
- Testing and quality assurance
- Translations

**How to become a Contributor:**
1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Submit a pull request or contribute in any way listed above
3. Your name will be added to [CONTRIBUTORS.md](CONTRIBUTORS.md)

### Maintainers

Maintainers have write access to the repository and are responsible for:

- Reviewing and merging pull requests
- Triaging issues and discussions
- Ensuring code quality and test coverage
- Making release decisions
- Guiding the project roadmap
- Enforcing the Code of Conduct

**Current Maintainers:**

| Name | GitHub | Role | Focus Area |
|------|--------|------|------------|
| Fernando Boiero | [@fboiero](https://github.com/fboiero) | Lead Maintainer | Core, Architecture |

### Lead Maintainer

The Lead Maintainer has final authority on project decisions when consensus cannot be reached. Responsibilities include:

- Breaking ties in disputed decisions
- Approving new maintainers
- Managing releases and versioning
- Representing the project externally

**Current Lead Maintainer:** Fernando Boiero ([@fboiero](https://github.com/fboiero))

---

## Decision Making

### Consensus-Based

Most decisions are made through consensus:

1. **Proposal**: Open an issue or discussion
2. **Discussion**: Community provides feedback
3. **Refinement**: Author incorporates feedback
4. **Approval**: Maintainers approve or request changes
5. **Implementation**: Changes are merged

### Lazy Consensus

For routine decisions (bug fixes, minor improvements):

- A maintainer approves the change
- If no objections within 48 hours, the change is merged
- Any maintainer can request extended review

### Voting

For significant decisions (architecture changes, new maintainers, policy changes):

- Proposals are announced in GitHub Discussions
- Voting period: 7 days minimum
- Approval requires: majority of active maintainers
- Lead Maintainer breaks ties

### RFC Process

For major changes, we use a Request for Comments (RFC) process:

1. **Draft RFC**: Create issue with `[RFC]` prefix
2. **Discussion Period**: Minimum 14 days
3. **Final Comment Period**: 7 days for last feedback
4. **Decision**: Maintainers vote to accept, reject, or revise
5. **Implementation**: Track in GitHub Projects

---

## Becoming a Maintainer

Contributors may be nominated for maintainer status based on:

### Criteria

- **Sustained contributions**: Regular quality contributions over 3+ months
- **Code quality**: Demonstrates understanding of codebase and standards
- **Community engagement**: Helpful in issues, discussions, and reviews
- **Reliability**: Responsive and dependable
- **Alignment**: Understands and supports project goals
- **Trust**: Maintainers trust their judgment

### Process

1. **Nomination**: Existing maintainer nominates contributor
2. **Discussion**: Private maintainer discussion (7 days)
3. **Vote**: Requires unanimous approval from current maintainers
4. **Invitation**: Lead Maintainer extends invitation
5. **Onboarding**: New maintainer receives write access and guidance

### Expectations

Maintainers are expected to:

- Review PRs within 5 business days
- Participate in maintainer discussions
- Follow the Code of Conduct
- Mentor new contributors
- Communicate absences in advance

### Stepping Down

Maintainers may step down at any time by notifying the Lead Maintainer. Inactive maintainers (no activity for 6 months) may be moved to emeritus status after discussion.

---

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md). Violations should be reported to fboiero@frvm.utn.edu.ar.

---

## Project Direction

### Roadmap

The project roadmap is maintained in [ROADMAP.md](ROADMAP.md) and updated quarterly. Major roadmap changes require:

1. RFC proposal
2. Community feedback period
3. Maintainer approval

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Major (X.0.0)**: Breaking changes
- **Minor (x.Y.0)**: New features, backwards compatible
- **Patch (x.y.Z)**: Bug fixes

Release decisions are made by maintainers with Lead Maintainer approval.

### Deprecation

Before removing features:

1. Mark as deprecated in documentation
2. Emit deprecation warnings for 1 minor version minimum
3. Announce in release notes
4. Remove in next major version

---

## Communication

### Official Channels

| Channel | Purpose |
|---------|---------|
| [GitHub Issues](https://github.com/fboiero/MIESC/issues) | Bug reports, feature requests |
| [GitHub Discussions](https://github.com/fboiero/MIESC/discussions) | Questions, ideas, community |
| Email: fboiero@frvm.utn.edu.ar | Private maintainer contact |

### Meetings

Currently, MIESC does not hold regular community meetings. This may change as the community grows.

---

## Licensing

All contributions must be compatible with [AGPL-3.0](LICENSE). By contributing, you agree to license your contribution under AGPL-3.0.

---

## Changes to Governance

This governance document may be amended through the RFC process:

1. Propose changes via GitHub Discussion with `[Governance]` tag
2. 14-day discussion period
3. Maintainer vote (requires unanimous approval)
4. Lead Maintainer implements changes

---

## Acknowledgments

This governance model is inspired by:

- [Node.js Project Governance](https://github.com/nodejs/node/blob/main/GOVERNANCE.md)
- [Kubernetes Governance](https://github.com/kubernetes/community/blob/master/governance.md)
- [Apache Software Foundation](https://www.apache.org/foundation/governance/)
- [CNCF Project Governance](https://github.com/cncf/project-template)

---

*Last updated: February 2026*

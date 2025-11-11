"""
Maturity Analyzer - Layer 7 (Audit Readiness)

Analyzes codebase maturity via Git metrics.

Metrics:
- Codebase age
- Commit frequency
- Number of contributors
- Time since last major change
- Code stability indicators

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL v3
"""
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class MaturityAnalyzer:
    """
    Analyzes code maturity through Git history

    Indicators:
    - Age of codebase (first commit to now)
    - Total commits
    - Number of contributors
    - Commit frequency
    - Time since last major change
    - Stability score
    """

    def __init__(self):
        """Initialize MaturityAnalyzer"""
        self.maturity_threshold = 0.6  # 60% maturity score to pass

    def _run_git_command(self, cmd: List[str], project_root: str) -> str:
        """
        Execute git command safely

        Args:
            cmd: Git command as list (without 'git')
            project_root: Path to project root

        Returns:
            Command output as string
        """
        try:
            result = subprocess.run(
                ['git'] + cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"Git command timed out: {' '.join(cmd)}")
            return ""
        except Exception as e:
            logger.error(f"Error running git command: {e}")
            return ""

    def analyze_code_maturity(self, project_root: str) -> Dict[str, Any]:
        """
        Analyze Git history for maturity metrics

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'age_days': int,
                'total_commits': int,
                'contributors': int,
                'contributors_list': List[str],
                'commits_last_90_days': int,
                'days_since_last_commit': int,
                'maturity_score': float (0-1),
                'passes_threshold': bool,
                'maturity_level': str
            }
        """
        try:
            logger.info(f"Analyzing code maturity in {project_root}")

            # Check if it's a git repository
            git_dir = Path(project_root) / '.git'
            if not git_dir.exists():
                return {
                    'error': 'Not a git repository',
                    'passes_threshold': False,
                    'recommendation': 'Initialize git repository for version control'
                }

            # 1. Age of codebase (first commit to now)
            first_commit_date = self._run_git_command(
                ['log', '--reverse', '--format=%ct', '--max-parents=0'],
                project_root
            )

            if first_commit_date:
                first_commit_ts = int(first_commit_date.split('\n')[0])
                age_days = (datetime.now().timestamp() - first_commit_ts) / 86400
            else:
                age_days = 0

            # 2. Total commits
            total_commits_str = self._run_git_command(
                ['rev-list', '--count', 'HEAD'],
                project_root
            )
            total_commits = int(total_commits_str) if total_commits_str else 0

            # 3. Contributors
            contributors_output = self._run_git_command(
                ['shortlog', '-sn', '--all'],
                project_root
            )

            contributors_list = []
            if contributors_output:
                for line in contributors_output.split('\n'):
                    if line.strip():
                        # Format: "  123  Author Name"
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            contributors_list.append(parts[1])

            contributors = len(contributors_list)

            # 4. Recent activity (last 90 days)
            recent_commits_str = self._run_git_command(
                ['rev-list', '--count', '--since=90.days.ago', 'HEAD'],
                project_root
            )
            commits_last_90_days = int(recent_commits_str) if recent_commits_str else 0

            # 5. Days since last commit
            last_commit_date = self._run_git_command(
                ['log', '-1', '--format=%ct'],
                project_root
            )

            if last_commit_date:
                last_commit_ts = int(last_commit_date)
                days_since_last = (datetime.now().timestamp() - last_commit_ts) / 86400
            else:
                days_since_last = 999

            # Calculate maturity score
            maturity_factors = {
                'age': min(age_days / 90, 1.0),  # 90 days = mature
                'commits': min(total_commits / 50, 1.0),  # 50 commits = active development
                'contributors': min(contributors / 3, 1.0),  # 3+ contributors = collaborative
                'recent_activity': min(commits_last_90_days / 10, 1.0),  # 10+ commits in 90 days = active
                'freshness': 1.0 if days_since_last < 30 else 0.5  # Updated recently
            }

            maturity_score = sum(maturity_factors.values()) / len(maturity_factors)

            # Determine maturity level
            if maturity_score >= 0.8:
                maturity_level = "mature"
            elif maturity_score >= 0.6:
                maturity_level = "developing"
            elif maturity_score >= 0.4:
                maturity_level = "early"
            else:
                maturity_level = "immature"

            passes = maturity_score >= self.maturity_threshold

            logger.info(f"Maturity score: {maturity_score:.2f} ({maturity_level})")
            logger.info(f"Age: {age_days:.0f} days, Commits: {total_commits}, Contributors: {contributors}")

            return {
                'age_days': int(age_days),
                'total_commits': total_commits,
                'contributors': contributors,
                'contributors_list': contributors_list[:10],  # Limit to 10
                'commits_last_90_days': commits_last_90_days,
                'days_since_last_commit': int(days_since_last),
                'maturity_score': round(maturity_score, 2),
                'maturity_level': maturity_level,
                'passes_threshold': passes,
                'threshold': self.maturity_threshold,
                'factors': {k: round(v, 2) for k, v in maturity_factors.items()}
            }

        except ValueError as e:
            logger.error(f"Error parsing git output: {e}")
            return {
                'error': f'Git parsing error: {e}',
                'passes_threshold': False
            }
        except Exception as e:
            logger.error(f"Error analyzing code maturity: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_commit_patterns(self, project_root: str) -> Dict[str, Any]:
        """
        Analyze commit patterns for stability indicators

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'average_commits_per_week': float,
                'commit_frequency_stable': bool,
                'large_commits_ratio': float,
                'stability_score': float (0-1)
            }
        """
        try:
            logger.info("Analyzing commit patterns")

            # Get commits from last 6 months with stats
            commits_output = self._run_git_command(
                ['log', '--oneline', '--shortstat', '--since=6.months.ago'],
                project_root
            )

            if not commits_output:
                return {
                    'error': 'No recent commits found',
                    'stability_score': 0.0
                }

            # Count commits
            commit_lines = [l for l in commits_output.split('\n') if l.strip() and not 'changed' in l]
            total_commits = len(commit_lines)

            # Calculate average commits per week (26 weeks in 6 months)
            avg_commits_per_week = total_commits / 26.0

            # Frequency is stable if averaging 1-5 commits per week
            frequency_stable = 1.0 <= avg_commits_per_week <= 5.0

            # Count large commits (>200 lines changed)
            large_commits = 0
            stat_lines = [l for l in commits_output.split('\n') if 'changed' in l]

            for line in stat_lines:
                # Parse " 5 files changed, 123 insertions(+), 45 deletions(-)"
                if 'insertion' in line or 'deletion' in line:
                    parts = line.split(',')
                    total_lines = 0
                    for part in parts:
                        if 'insertion' in part or 'deletion' in part:
                            nums = ''.join(c for c in part if c.isdigit())
                            if nums:
                                total_lines += int(nums)
                    if total_lines > 200:
                        large_commits += 1

            large_commits_ratio = large_commits / total_commits if total_commits > 0 else 0

            # Stability score: lower large commits ratio = more stable
            stability_score = 1.0 - (large_commits_ratio * 0.5)  # Penalty for large commits

            if frequency_stable:
                stability_score *= 1.2  # Bonus for stable frequency

            stability_score = min(stability_score, 1.0)

            logger.info(f"Stability score: {stability_score:.2f}")

            return {
                'average_commits_per_week': round(avg_commits_per_week, 2),
                'commit_frequency_stable': frequency_stable,
                'large_commits_ratio': round(large_commits_ratio, 2),
                'stability_score': round(stability_score, 2)
            }

        except Exception as e:
            logger.error(f"Error analyzing commit patterns: {e}")
            return {
                'error': str(e),
                'stability_score': 0.0
            }

    def analyze_all(self, project_root: str) -> Dict[str, Any]:
        """
        Complete maturity analysis

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'maturity': {...},
                'patterns': {...},
                'overall_score': float (0-1),
                'passes_audit_readiness': bool
            }
        """
        maturity_result = self.analyze_code_maturity(project_root)
        patterns_result = self.analyze_commit_patterns(project_root)

        # Overall score: 70% maturity + 30% stability
        maturity_score = maturity_result.get('maturity_score', 0)
        stability_score = patterns_result.get('stability_score', 0)

        overall_score = maturity_score * 0.7 + stability_score * 0.3

        passes = maturity_result.get('passes_threshold', False)

        logger.info(f"Maturity overall score: {overall_score:.2f}")

        return {
            'maturity': maturity_result,
            'patterns': patterns_result,
            'overall_score': round(overall_score, 2),
            'passes_audit_readiness': passes
        }

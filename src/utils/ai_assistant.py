#!/usr/bin/env python3
"""
AI Assistant for Smart Contract Audit Triage
Processes findings from static analyzers and provides intelligent classification.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, environment variables must be set manually

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    openai = None  # type: ignore
    OPENAI_AVAILABLE = False


class AIAuditAssistant:
    """AI-powered audit finding classifier and analyzer."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")
        openai.api_key = self.api_key

    def classify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a single audit finding using AI.

        Args:
            finding: Dictionary containing finding details

        Returns:
            Enhanced finding with AI classification
        """
        prompt = f"""
You are an expert smart contract auditor. Analyze this finding from a static analyzer:

**Detector**: {finding.get('check', 'Unknown')}
**Severity**: {finding.get('impact', 'Unknown')}
**Confidence**: {finding.get('confidence', 'Unknown')}
**Description**: {finding.get('description', 'No description')}
**Location**: {finding.get('elements', [])}

Provide:
1. **Classification**: CRITICAL / HIGH / MEDIUM / LOW / FALSE_POSITIVE
2. **Real Risk**: Actual exploitability (0-10 scale)
3. **Justification**: One clear sentence
4. **PoC Hint**: If critical/high, suggest exploit approach (1 line)
5. **Mitigation**: Concrete fix recommendation

Output as JSON:
{{
  "classification": "...",
  "risk_score": X,
  "justification": "...",
  "poc_hint": "...",
  "mitigation": "..."
}}
"""

        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert smart contract security auditor."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )

            ai_response = response.choices[0].message.content
            # Extract JSON from response
            ai_data = json.loads(ai_response.strip().replace("```json", "").replace("```", ""))

            finding['ai_classification'] = ai_data
            return finding

        except Exception as e:
            print(f"Warning: AI classification failed: {e}")
            finding['ai_classification'] = {
                "classification": "UNKNOWN",
                "risk_score": 0,
                "justification": f"AI processing error: {str(e)}",
                "poc_hint": "N/A",
                "mitigation": "Manual review required"
            }
            return finding

    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on location and type."""
        seen = set()
        unique = []

        for finding in findings:
            key = (
                finding.get('check'),
                str(finding.get('elements', []))[:100]  # First 100 chars of location
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by AI risk score and severity."""
        def get_priority(f):
            ai_class = f.get('ai_classification', {})
            risk = ai_class.get('risk_score', 0)
            severity_map = {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
            severity = severity_map.get(f.get('impact', 'Low'), 0)
            return (risk, severity)

        return sorted(findings, key=get_priority, reverse=True)

    def generate_summary(self, findings: List[Dict]) -> str:
        """Generate markdown summary of audit findings."""
        total = len(findings)
        critical = sum(1 for f in findings if f.get('ai_classification', {}).get('classification') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('ai_classification', {}).get('classification') == 'HIGH')
        medium = sum(1 for f in findings if f.get('ai_classification', {}).get('classification') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('ai_classification', {}).get('classification') == 'LOW')
        fp = sum(1 for f in findings if f.get('ai_classification', {}).get('classification') == 'FALSE_POSITIVE')

        summary = f"""# Smart Contract Audit Report (AI-Enhanced)

## Executive Summary

- **Total Findings**: {total}
- **Critical**: {critical} 🔴
- **High**: {high} 🟠
- **Medium**: {medium} 🟡
- **Low**: {low} 🟢
- **False Positives**: {fp} ⚪

## Top Priority Issues

"""

        # Add top 5 issues
        top_issues = self.prioritize_findings(findings)[:5]
        for i, finding in enumerate(top_issues, 1):
            ai_class = finding.get('ai_classification', {})
            summary += f"""
### {i}. {finding.get('check', 'Unknown Issue')}

- **Severity**: {finding.get('impact', 'Unknown')}
- **AI Classification**: {ai_class.get('classification', 'UNKNOWN')}
- **Risk Score**: {ai_class.get('risk_score', 0)}/10
- **Justification**: {ai_class.get('justification', 'N/A')}
- **Mitigation**: {ai_class.get('mitigation', 'N/A')}
{f"- **PoC Hint**: {ai_class.get('poc_hint')}" if ai_class.get('poc_hint') != 'N/A' else ''}

---
"""

        return summary


def main():
    parser = argparse.ArgumentParser(description="AI Assistant for Smart Contract Audit Triage")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file (e.g., from Slither)")
    parser.add_argument("--output", default="analysis/ai_report.md", help="Output report path")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")

    args = parser.parse_args()

    # Load findings
    print(f"Loading findings from {args.findings}...")
    with open(args.findings, 'r') as f:
        data = json.load(f)

    findings = data.get('results', {}).get('detectors', [])
    print(f"Found {len(findings)} findings")

    # Initialize AI assistant
    print(f"Initializing AI assistant (model: {args.model})...")
    assistant = AIAuditAssistant(model=args.model)

    # Deduplicate
    findings = assistant.deduplicate_findings(findings)
    print(f"After deduplication: {len(findings)} unique findings")

    # Classify each finding
    print("Classifying findings with AI...")
    classified = []
    for i, finding in enumerate(findings, 1):
        print(f"  [{i}/{len(findings)}] Classifying {finding.get('check', 'Unknown')}...")
        classified_finding = assistant.classify_finding(finding)
        classified.append(classified_finding)

    # Prioritize
    classified = assistant.prioritize_findings(classified)

    # Generate summary
    print("Generating report...")
    summary = assistant.generate_summary(classified)

    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write(summary)

    # Save detailed JSON
    json_output = output_path.with_suffix('.json')
    with open(json_output, 'w') as f:
        json.dump({
            'summary': {
                'total': len(classified),
                'critical': sum(1 for f in classified if f.get('ai_classification', {}).get('classification') == 'CRITICAL'),
                'high': sum(1 for f in classified if f.get('ai_classification', {}).get('classification') == 'HIGH'),
                'medium': sum(1 for f in classified if f.get('ai_classification', {}).get('classification') == 'MEDIUM'),
                'low': sum(1 for f in classified if f.get('ai_classification', {}).get('classification') == 'LOW'),
                'false_positives': sum(1 for f in classified if f.get('ai_classification', {}).get('classification') == 'FALSE_POSITIVE'),
            },
            'findings': classified
        }, f, indent=2)

    print(f"\n✅ Report generated:")
    print(f"   - Markdown: {output_path}")
    print(f"   - JSON: {json_output}")


if __name__ == "__main__":
    main()

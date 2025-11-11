#!/usr/bin/env python3
"""
AI Assistant for Xaudit Framework
Provides AI-powered analysis, classification, and prioritization of security findings.
Supports both OpenAI API and local Llama models via Ollama.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import os

# Try importing OpenAI
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    print("Warning: openai package not installed. Install with: pip install openai")

# Try importing ollama for local models
try:
    import ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class Finding:
    """Structured finding data."""
    id: str
    detector: str
    title: str
    description: str
    severity_original: str
    severity_ai: Optional[str] = None
    confidence: Optional[str] = None
    impact_score: Optional[float] = None  # 0-10 scale
    exploitability: Optional[float] = None  # 0-10 scale
    priority: Optional[int] = None  # 1-10 (10 = highest)
    false_positive_likelihood: Optional[float] = None  # 0-1 probability
    recommendation: Optional[str] = None
    poc_hint: Optional[str] = None
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


class AIAssistant:
    """AI-powered security analysis assistant."""

    def __init__(self, model: str = "gpt-4o-mini", provider: str = "openai"):
        """
        Initialize AI assistant.

        Args:
            model: Model name (e.g., 'gpt-4o-mini', 'llama3.2', 'mistral')
            provider: 'openai' or 'ollama'
        """
        self.model = model
        self.provider = provider

        if provider == "openai":
            if not HAS_OPENAI:
                raise ImportError("OpenAI package not installed")
            self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        elif provider == "ollama":
            if not HAS_OLLAMA:
                raise ImportError("Ollama package not installed. Install with: pip install ollama")
            self.client = ollama
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def _call_llm(self, messages: List[Dict[str, str]], temperature: float = 0.3) -> str:
        """Call the LLM with the given messages."""
        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=1500
                )
                return response.choices[0].message.content
            elif self.provider == "ollama":
                response = self.client.chat(
                    model=self.model,
                    messages=messages,
                    options={"temperature": temperature}
                )
                return response['message']['content']
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return None

    def classify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a security finding using AI.

        Returns:
            Dict with: severity, impact_score, exploitability, priority,
                      false_positive_likelihood, recommendation, poc_hint
        """
        prompt = f"""
Analyze this smart contract security finding and provide a detailed classification.

**Finding Details:**
- Detector: {finding.get('check', finding.get('detector', 'Unknown'))}
- Impact: {finding.get('impact', 'Unknown')}
- Confidence: {finding.get('confidence', 'Unknown')}
- Description: {finding.get('description', finding.get('title', 'No description'))[:500]}

**Your Task:**
Provide a JSON response with the following fields:
1. **severity**: One of [CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, FALSE_POSITIVE]
2. **impact_score**: Real exploitability impact (0-10 scale)
3. **exploitability**: How easy to exploit (0-10, where 10 = trivially exploitable)
4. **priority**: Overall priority for remediation (1-10, where 10 = fix immediately)
5. **false_positive_likelihood**: Probability this is a false positive (0.0-1.0)
6. **recommendation**: Brief mitigation recommendation (1-2 sentences)
7. **poc_hint**: If critical/high, suggest an exploit approach (or "N/A")

**Context:**
- CRITICAL: Direct fund loss, complete contract compromise
- HIGH: Significant vulnerability with clear exploit path
- MEDIUM: Vulnerability requiring specific conditions
- LOW: Minor issue or best practice violation
- INFORMATIONAL: Code quality or gas optimization
- FALSE_POSITIVE: Likely not a real vulnerability

Respond ONLY with valid JSON.
"""

        messages = [
            {"role": "system", "content": "You are an expert smart contract security auditor specializing in EVM vulnerabilities. Provide precise, actionable analysis."},
            {"role": "user", "content": prompt}
        ]

        response = self._call_llm(messages, temperature=0.2)

        if not response:
            return self._default_classification(finding)

        try:
            # Try to extract JSON from response
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()

            classification = json.loads(response)
            return classification
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse AI response as JSON: {e}")
            return self._default_classification(finding)

    def _default_classification(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback classification if AI fails."""
        impact = finding.get('impact', 'Low').upper()
        severity_map = {
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFORMATIONAL': 'INFORMATIONAL'
        }

        return {
            'severity': severity_map.get(impact, 'MEDIUM'),
            'impact_score': 5.0,
            'exploitability': 5.0,
            'priority': 5,
            'false_positive_likelihood': 0.3,
            'recommendation': 'Review this finding manually.',
            'poc_hint': 'N/A'
        }

    def generate_summary(self, findings: List[Finding]) -> str:
        """Generate executive summary of all findings."""
        if not findings:
            return "No findings to summarize."

        # Count by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity_ai or f.severity_original
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Get top priority findings
        prioritized = sorted(
            [f for f in findings if f.priority and f.priority >= 7],
            key=lambda x: x.priority,
            reverse=True
        )[:5]

        prompt = f"""
Generate an executive summary for a smart contract security audit.

**Statistics:**
- Total findings: {len(findings)}
- Critical: {severity_counts.get('CRITICAL', 0)}
- High: {severity_counts.get('HIGH', 0)}
- Medium: {severity_counts.get('MEDIUM', 0)}
- Low: {severity_counts.get('LOW', 0)}
- Informational: {severity_counts.get('INFORMATIONAL', 0)}

**Top Priority Findings:**
{chr(10).join([f"- {f.detector}: {f.title[:100]}" for f in prioritized[:3]])}

**Your Task:**
Write a concise executive summary (3-4 paragraphs) covering:
1. Overall security posture
2. Critical risks that require immediate attention
3. Key recommendations
4. Overall risk rating (Critical/High/Medium/Low)

Use professional, clear language suitable for both technical and non-technical stakeholders.
"""

        messages = [
            {"role": "system", "content": "You are a senior security auditor writing executive summaries for clients."},
            {"role": "user", "content": prompt}
        ]

        summary = self._call_llm(messages, temperature=0.4)
        return summary or "Unable to generate summary."

    def prioritize_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Sort findings by priority (highest first).
        Priority is calculated from: severity + impact_score + exploitability - false_positive_likelihood
        """
        def priority_score(f: Finding) -> float:
            severity_weights = {
                'CRITICAL': 10,
                'HIGH': 7,
                'MEDIUM': 4,
                'LOW': 2,
                'INFORMATIONAL': 1,
                'FALSE_POSITIVE': 0
            }

            sev_weight = severity_weights.get(f.severity_ai or f.severity_original, 3)
            impact = f.impact_score or 5.0
            exploit = f.exploitability or 5.0
            fp_penalty = (f.false_positive_likelihood or 0.0) * 10

            return (sev_weight * 2) + impact + exploit - fp_penalty

        # Calculate priority scores
        for f in findings:
            f.priority = int(min(10, max(1, priority_score(f))))

        # Sort by priority
        return sorted(findings, key=lambda x: x.priority, reverse=True)


def parse_slither_json(json_path: Path) -> List[Finding]:
    """Parse Slither JSON output into Finding objects."""
    with open(json_path) as f:
        data = json.load(f)

    findings = []
    detectors = data.get('results', {}).get('detectors', [])

    for i, det in enumerate(detectors):
        finding = Finding(
            id=f"SLITHER-{i+1:03d}",
            detector=det.get('check', 'unknown'),
            title=det.get('description', 'No title')[:200],
            description=det.get('description', ''),
            severity_original=det.get('impact', 'Low').upper(),
            confidence=det.get('confidence', 'Medium')
        )
        findings.append(finding)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="AI Assistant for Xaudit Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Classify Slither findings with OpenAI
  python ai_assistant.py --input slither_results.json --output triage_report.md

  # Use local Llama model via Ollama
  python ai_assistant.py --input slither_results.json --provider ollama --model llama3.2

  # Generate executive summary only
  python ai_assistant.py --input slither_results.json --summary-only
        """
    )

    parser.add_argument("--input", "-i", required=True, help="Path to Slither JSON results")
    parser.add_argument("--output", "-o", default="ai_triage_report.md", help="Output report path")
    parser.add_argument("--provider", choices=["openai", "ollama"], default="openai", help="LLM provider")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name (gpt-4o-mini, llama3.2, etc.)")
    parser.add_argument("--summary-only", action="store_true", help="Generate summary only, skip classification")
    parser.add_argument("--json-output", help="Save findings as JSON")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    print(f"Loading findings from: {input_path}")
    findings = parse_slither_json(input_path)
    print(f"Loaded {len(findings)} findings")

    if not findings:
        print("No findings to process")
        sys.exit(0)

    # Initialize AI assistant
    try:
        assistant = AIAssistant(model=args.model, provider=args.provider)
        print(f"Using {args.provider} with model: {args.model}")
    except Exception as e:
        print(f"Error initializing AI assistant: {e}")
        sys.exit(1)

    # Classify findings (unless summary-only)
    if not args.summary_only:
        print("\nClassifying findings with AI...")
        for i, finding in enumerate(findings, 1):
            print(f"  Processing {i}/{len(findings)}: {finding.detector}")
            classification = assistant.classify_finding(asdict(finding))

            # Update finding with AI classification
            finding.severity_ai = classification.get('severity')
            finding.impact_score = classification.get('impact_score')
            finding.exploitability = classification.get('exploitability')
            finding.false_positive_likelihood = classification.get('false_positive_likelihood')
            finding.recommendation = classification.get('recommendation')
            finding.poc_hint = classification.get('poc_hint')

        # Prioritize findings
        findings = assistant.prioritize_findings(findings)

    # Generate summary
    print("\nGenerating executive summary...")
    summary = assistant.generate_summary(findings)

    # Generate markdown report
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        f.write("# 🔍 Xaudit AI-Assisted Security Analysis Report\n\n")
        f.write(f"**Generated:** {Path(args.input).name}\n")
        f.write(f"**AI Model:** {args.provider} / {args.model}\n\n")

        f.write("## Executive Summary\n\n")
        f.write(summary)
        f.write("\n\n")

        if not args.summary_only:
            # Statistics
            f.write("## Statistics\n\n")
            severity_counts = {}
            for finding in findings:
                sev = finding.severity_ai or finding.severity_original
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            f.write(f"- **Total Findings:** {len(findings)}\n")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'FALSE_POSITIVE']:
                if severity_counts.get(sev, 0) > 0:
                    f.write(f"- **{sev}:** {severity_counts[sev]}\n")
            f.write("\n")

            # Detailed findings
            f.write("## Prioritized Findings\n\n")
            for finding in findings:
                if finding.severity_ai == 'FALSE_POSITIVE':
                    continue

                f.write(f"### [{finding.id}] {finding.detector}\n\n")
                f.write(f"**Severity:** {finding.severity_ai or finding.severity_original} ")
                f.write(f"(Priority: {finding.priority}/10)\n\n")

                if finding.impact_score:
                    f.write(f"- **Impact Score:** {finding.impact_score:.1f}/10\n")
                if finding.exploitability:
                    f.write(f"- **Exploitability:** {finding.exploitability:.1f}/10\n")
                if finding.false_positive_likelihood:
                    f.write(f"- **False Positive Likelihood:** {finding.false_positive_likelihood:.1%}\n")

                f.write(f"\n**Description:**\n{finding.description[:300]}\n\n")

                if finding.recommendation:
                    f.write(f"**Recommendation:**\n{finding.recommendation}\n\n")

                if finding.poc_hint and finding.poc_hint != "N/A":
                    f.write(f"**PoC Hint:**\n{finding.poc_hint}\n\n")

                f.write("---\n\n")

            # False positives section
            false_positives = [f for f in findings if f.severity_ai == 'FALSE_POSITIVE']
            if false_positives:
                f.write("## Likely False Positives\n\n")
                for finding in false_positives:
                    f.write(f"- [{finding.id}] {finding.detector}: {finding.title[:100]}\n")
                f.write("\n")

        f.write("---\n\n")
        f.write("*Generated by Xaudit AI Assistant*\n")

    print(f"\n✅ Report saved to: {output_path}")

    # Save JSON if requested
    if args.json_output:
        json_path = Path(args.json_output)
        with open(json_path, 'w') as f:
            json.dump([asdict(f) for f in findings], f, indent=2)
        print(f"✅ JSON output saved to: {json_path}")


if __name__ == "__main__":
    main()

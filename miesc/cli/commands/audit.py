"""
MIESC CLI - Audit Commands

Commands for running security audits on smart contracts.

Author: Fernando Boiero
License: AGPL-3.0
"""

import concurrent.futures
import glob as glob_module
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import click

from miesc import __version__ as VERSION
from miesc.cli.constants import ADAPTER_MAP, AVAILABLE_PROFILES, LAYERS, QUICK_TOOLS
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    get_correlation_api,
    get_ml_orchestrator,
    get_profile,
    info,
    load_profiles,
    print_banner,
    run_layer,
    run_plugins,
    run_tool,
    success,
    summarize_findings,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table

logger = logging.getLogger(__name__)


def _apply_deep_profile_config(config: Any, profile_name: str | None) -> tuple[Any, Dict[str, Any]]:
    """Apply profile settings that are safe for agentic deep audit."""
    if not profile_name:
        return config, {}

    profile = get_profile(profile_name)
    if not profile:
        raise click.ClickException(f"Profile '{profile_name}' not found")

    if "timeout" in profile:
        config.timeout_seconds = int(profile["timeout"])
    if "max_iterations" in profile:
        config.max_iterations = int(profile["max_iterations"])
    if "enable_agentic_invariants" in profile:
        config.enable_agentic_invariants = bool(profile["enable_agentic_invariants"])

    ensemble = profile.get("agentic_ensemble", {})
    if isinstance(ensemble, dict):
        if "allow_remote" in ensemble:
            config.agentic_invariants_allow_remote = bool(ensemble["allow_remote"])
        if "local_first" in ensemble:
            config.llm_provider = "auto" if ensemble["local_first"] else config.llm_provider

    return config, profile


def _profile_uses_agentic_path(profile: Dict[str, Any]) -> bool:
    """Return True for profiles that require agentic audit semantics."""
    return bool(profile.get("agentic_ensemble") or profile.get("enable_agentic_invariants"))


def _run_agentic_audit_profile(
    profile_name: str,
    profile: Dict[str, Any],
    contract: str,
    output: str | None,
    fmt: str,
    ci: bool,
) -> None:
    """Run an agentic profile through DeepAuditAgent instead of raw tool loops."""
    from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

    config = DeepAuditConfig(
        timeout_seconds=int(profile.get("timeout", 600)),
        max_iterations=int(profile.get("max_iterations", 5)),
        enable_llm=bool(profile.get("enable_ai_triage", False)),
        enable_rag=not bool(profile.get("skip_rag", False)),
    )
    config, _profile_config = _apply_deep_profile_config(config, profile_name)
    agent = DeepAuditAgent(config=config)

    info("Running agentic profile path")
    result = agent.analyze(contract)
    findings = result.get("findings", [])
    all_results = [
        {
            "tool": "miesc-agentic-profile",
            "status": "success",
            "findings": findings,
            "metadata": result.get("metadata", {}),
        }
    ]
    summary = summarize_findings(all_results)

    if output:
        if fmt == "sarif":
            data: Any = _to_sarif(all_results)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
        else:
            data = {
                "profile": profile_name,
                "agentic": True,
                "result": result,
                "results": all_results,
                "summary": summary,
                "version": VERSION,
            }
        mode = "w"
        with open(output, mode, encoding="utf-8") as f:
            if fmt == "markdown":
                f.write(str(data))
            else:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    if ci and (summary.get("CRITICAL", 0) > 0 or summary.get("HIGH", 0) > 0):
        error(
            f"Found {summary.get('CRITICAL', 0)} critical and {summary.get('HIGH', 0)} high issues"
        )
        sys.exit(1)


# =============================================================================
# Output Format Converters
# =============================================================================


def _to_sarif(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert results to SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MIESC",
                        "version": VERSION,
                        "informationUri": "https://github.com/fboiero/MIESC",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_ids = set()

    for result in results:
        tool_name = result.get("tool", "unknown")

        for finding in result.get("findings", []):
            rule_id = finding.get("type", finding.get("id", finding.get("title", "unknown")))

            # Add rule if not already added
            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    {
                        "id": rule_id,
                        "name": finding.get("title", rule_id),
                        "shortDescription": {"text": finding.get("message", rule_id)},
                        "fullDescription": {"text": finding.get("description", "")},
                        "helpUri": (
                            finding.get("references", [""])[0] if finding.get("references") else ""
                        ),
                        "properties": {
                            "tool": tool_name,
                            "canonicalCategory": finding.get("canonical_category", ""),
                        },
                    }
                )
                rule_ids.add(rule_id)

            # Map severity
            severity = str(finding.get("severity", "INFO")).upper()
            level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
                severity, "note"
            )

            # Get location
            location = finding.get("location", {})
            if isinstance(location, dict):
                file_path = location.get("file", result.get("contract", "unknown"))
                line = location.get("line", 1)
            else:
                file_path = result.get("contract", "unknown")
                line = 1

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding.get("description", finding.get("message", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": max(1, int(line))},
                            }
                        }
                    ],
                    "properties": {
                        "tool": tool_name,
                        "confidence": finding.get("confidence", 0.5),
                        # v5.2.0: intelligence engine metadata in SARIF
                        "canonicalCategory": finding.get("canonical_category", ""),
                        "confirmingTools": finding.get("confirming_tools", []),
                        "toolCount": finding.get("tool_count", 1),
                        "crossValidatedStatic": finding.get("cross_validated_static", False),
                        "crossValidatedLLM": finding.get("cross_validated_llm", False),
                        "fpSuppressed": finding.get("fp_suppressed", False),
                    },
                }
            )

    return sarif


def _to_markdown(results: List[Dict[str, Any]], contract: str) -> str:
    """Convert results to Markdown report."""
    summary = summarize_findings(results)
    total = sum(summary.values())

    # Count tools
    successful_tools = [r["tool"] for r in results if r.get("status") == "success"]
    failed_tools = [r["tool"] for r in results if r.get("status") != "success"]

    md = f"""# MIESC Security Audit Report

**Contract**: `{contract}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |
| Info | {summary['INFO']} |
| **Total** | **{total}** |

### Tools Executed

- **Successful**: {', '.join(successful_tools) if successful_tools else 'None'}
- **Failed/Unavailable**: {', '.join(failed_tools) if failed_tools else 'None'}

## Detailed Findings

"""

    for result in results:
        if result.get("findings"):
            tool_name = result.get("tool", "unknown").upper()
            md += f"### {tool_name}\n\n"

            for finding in result["findings"]:
                severity = finding.get("severity", "INFO")
                title = finding.get("title", finding.get("type", finding.get("id", "Unknown")))
                description = finding.get("description", finding.get("message", ""))

                md += f"**[{severity}]** {title}\n\n"
                md += f"{description}\n\n"

                # Location
                location = finding.get("location", {})
                if isinstance(location, dict) and location.get("file"):
                    md += f"- **Location**: `{location['file']}:{location.get('line', 0)}`\n"

                # Recommendation
                if finding.get("recommendation"):
                    md += f"- **Recommendation**: {finding['recommendation']}\n"

                # References
                if finding.get("swc_id"):
                    md += f"- **SWC**: {finding['swc_id']}\n"

                md += "\n---\n\n"

    md += """
## Appendix

### Tool Execution Details

| Tool | Status | Time (s) | Findings |
|------|--------|----------|----------|
"""

    for result in results:
        tool = result.get("tool", "unknown")
        status = result.get("status", "unknown")
        exec_time = result.get("execution_time", 0)
        findings_count = len(result.get("findings", []))
        md += f"| {tool} | {status} | {exec_time:.1f} | {findings_count} |\n"

    md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"

    return md


def _ml_result_to_markdown(result: Any, contract: str) -> str:
    """Convert ML analysis result to Markdown report."""
    summary = result.get_summary()

    md = f"""# MIESC ML-Enhanced Security Audit Report

**Contract**: `{contract}`
**Date**: {result.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}
**Risk Level**: {summary['risk_level']}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | {summary['total_findings']} |
| Critical | {summary['critical']} |
| High | {summary['high']} |
| Medium | {summary['medium']} |
| Low | {summary['low']} |
| False Positives Removed | {result.false_positives_removed} |
| Reduction Rate | {summary['reduction_rate']:.1f}% |

## ML Pipeline Metrics

- **Raw findings analyzed**: {result.total_raw_findings}
- **After FP filtering**: {len(result.ml_filtered_findings)}
- **Severity adjustments**: {result.severity_adjustments}
- **Vulnerability clusters**: {result.cluster_count}
- **Cross-validated findings**: {result.cross_validated}

## Tools Executed

- **Successful**: {', '.join(result.tools_success) if result.tools_success else 'None'}
- **Failed**: {', '.join(result.tools_failed) if result.tools_failed else 'None'}

## Detailed Findings

"""
    for finding in result.ml_filtered_findings[:20]:
        severity = finding.get("severity", "INFO").upper()
        title = finding.get("title", finding.get("type", finding.get("id", "Unknown")))
        description = finding.get("description", finding.get("message", ""))
        location = finding.get("location", {})

        md += f"### [{severity}] {title}\n\n"
        md += f"{description}\n\n"

        if isinstance(location, dict) and location.get("file"):
            md += f"- **Location**: `{location['file']}:{location.get('line', 0)}`\n"

        if finding.get("confidence"):
            md += f"- **Confidence**: {finding['confidence']:.2f}\n"

        if finding.get("tool"):
            md += f"- **Detected by**: {finding['tool']}\n"

        md += "\n---\n\n"

    if result.cluster_count > 0:
        md += "## Vulnerability Clusters\n\n"
        for i, cluster in enumerate(result.clusters[:5], 1):
            cluster_dict = cluster.to_dict() if hasattr(cluster, "to_dict") else {}
            md += f"### Cluster {i}: {cluster_dict.get('primary_type', 'Unknown')}\n"
            md += f"- Findings: {cluster_dict.get('count', 0)}\n"
            md += f"- Severity: {cluster_dict.get('max_severity', 'unknown')}\n\n"

    md += f"""
## Execution Details

- **Execution time**: {result.execution_time_ms/1000:.1f}s
- **ML processing time**: {result.ml_processing_time_ms/1000:.1f}s

---

*Generated by MIESC v{VERSION} with ML Pipeline*
"""
    return md


# =============================================================================
# Full Audit Helper Functions
# =============================================================================


def _run_full_audit_with_ml(
    contract: str,
    output: str | None,
    fmt: str,
    layer_list: list[int],
    timeout: int,
    orchestrator: Any,
    verify_fp: bool = False,
    verify_model: str | None = None,
    rank: bool = False,
    fp_strictness: str = "off",
    baseline_path: str | None = None,
    fail_on_new: bool = False,
) -> None:
    """Run full audit using ML Orchestrator."""
    # Determine tools from layers
    tools_to_run: list[str] = []
    for layer in layer_list:
        if layer in LAYERS:
            tools_to_run.extend(LAYERS[layer]["tools"])

    info(f"Running {len(tools_to_run)} tools with ML enhancement...")

    # Progress callback for Rich
    def progress_callback(stage: str, message: str, progress: float) -> None:
        if RICH_AVAILABLE:
            console.print(f"[dim]{stage}:[/dim] {message}")

    # Run ML-enhanced analysis
    try:
        result = orchestrator.analyze(
            contract_path=contract,
            tools=tools_to_run,
            timeout=timeout,
            progress_callback=progress_callback if RICH_AVAILABLE else None,
            fp_strictness=fp_strictness,
        )

        # Recall-safe benign-context verifier (opt-in) over the ML-filtered findings
        if verify_fp:
            try:
                from miesc.ml.benign_context_verifier import apply_to_results

                wrapped = [{"findings": list(result.ml_filtered_findings)}]
                d, fl = apply_to_results(wrapped, contract=contract, model=verify_model)
                result.ml_filtered_findings = wrapped[0]["findings"]
                mode = f"LLM {verify_model}" if verify_model else "rule-only"
                info(
                    f"verify-fp ({mode}): dropped {d} benign-context FP(s), "
                    f"flagged {fl} for review — real findings kept (recall-safe)"
                )
            except Exception as e:  # noqa: BLE001
                info(f"verify-fp skipped: {e}")

        # Display ML-enhanced summary
        summary_data = result.get_summary()
        if verify_fp:
            # The ML get_summary() is computed from internal counts and does not reflect
            # the post-hoc verifier; recompute the displayed totals from the filtered set.
            _sf = summarize_findings([{"tool": "ml", "findings": result.ml_filtered_findings}])
            summary_data["total_findings"] = sum(_sf.values())
            for _k in ("critical", "high", "medium", "low"):
                summary_data[_k] = _sf.get(_k.upper(), summary_data.get(_k, 0))

        if RICH_AVAILABLE:
            console.print("\n")

            # Main summary table
            table = Table(title="ML-Enhanced Audit Summary", box=box.ROUNDED)
            table.add_column("Metric", style="bold")
            table.add_column("Value", justify="right")

            table.add_row(
                "Risk Level",
                f"[{'red' if summary_data['risk_level'] in ['CRITICAL', 'HIGH'] else 'yellow'}]{summary_data['risk_level']}[/]",
            )
            table.add_row("Total Findings", str(summary_data["total_findings"]))
            table.add_row("Critical", f"[red]{summary_data['critical']}[/red]")
            table.add_row("High", f"[red]{summary_data['high']}[/red]")
            table.add_row("Medium", f"[yellow]{summary_data['medium']}[/yellow]")
            table.add_row("Low", f"[cyan]{summary_data['low']}[/cyan]")
            console.print(table)

            # ML metrics table
            ml_table = Table(title="ML Pipeline Metrics", box=box.SIMPLE)
            ml_table.add_column("Metric", style="dim")
            ml_table.add_column("Value", justify="right")

            ml_table.add_row("Raw Findings", str(result.total_raw_findings))
            ml_table.add_row(
                "False Positives Removed", f"[green]{result.false_positives_removed}[/green]"
            )
            ml_table.add_row("Reduction Rate", f"{summary_data['reduction_rate']:.1f}%")
            ml_table.add_row("Severity Adjustments", str(result.severity_adjustments))
            ml_table.add_row("Vulnerability Clusters", str(result.cluster_count))
            ml_table.add_row("Cross-Validated", str(result.cross_validated))
            console.print(ml_table)

            # Tools summary
            console.print(
                f"\n[dim]Tools: {len(result.tools_success)}/{len(result.tools_run)} successful[/dim]"
            )
            if result.tools_failed:
                console.print(f"[yellow]Failed: {', '.join(result.tools_failed)}[/yellow]")

            console.print(
                f"[dim]Execution time: {result.execution_time_ms/1000:.1f}s (ML: {result.ml_processing_time_ms/1000:.1f}s)[/dim]"
            )
        else:
            print("\n=== ML-Enhanced Audit Summary ===")
            print(f"Risk Level: {summary_data['risk_level']}")
            print(
                f"Total: {summary_data['total_findings']} (Critical: {summary_data['critical']}, High: {summary_data['high']})"
            )
            print(
                f"FPs Removed: {result.false_positives_removed} ({summary_data['reduction_rate']:.1f}% reduction)"
            )

        # Save output
        if output:
            if fmt == "json":
                data = result.to_dict()
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
            elif fmt == "markdown":
                data = _ml_result_to_markdown(result, contract)
                with open(output, "w", encoding="utf-8") as f:
                    f.write(data)
            elif fmt == "sarif":
                # Convert ML result to SARIF format
                all_results = [
                    {"tool": t, "findings": result.ml_filtered_findings, "status": "success"}
                    for t in result.tools_success[:1]
                ]  # Use first tool as source
                data = _to_sarif(all_results)
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            success(f"Report saved to {output}")

        # Baseline suppression gate
        if baseline_path:
            from miesc.cli.commands.baseline import apply_baseline_gate

            apply_baseline_gate(
                list(result.ml_filtered_findings),
                baseline_path,
                fail_on_new=fail_on_new,
            )

    except Exception as e:
        error(f"ML analysis failed: {e}")
        logger.exception("ML analysis error")
        info("Falling back to basic mode...")
        _run_full_audit_basic(
            contract,
            output,
            fmt,
            layer_list,
            timeout,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
        )


def _rank_report_findings(findings: dict[str, Any], *, contract: str) -> None:
    """Recall-safe triage on a correlation report's finding buckets (in place): order each
    list of findings by P(real). Never drops anything. No-ops without a trained model."""
    try:
        from miesc.ml.triage_ranker import TriageRanker
    except Exception as e:  # noqa: BLE001
        info(f"rank skipped: {e}")
        return
    ranker = TriageRanker()
    if not ranker.available():
        info("rank: no triage model — train with scripts/train_triage_model.py (order unchanged)")
        return
    cache: dict[str, str] = {}

    def code_for(f: dict[str, Any]) -> str:
        _loc = f.get("location")
        loc = _loc if isinstance(_loc, dict) else {}
        path = loc.get("file") or f.get("file") or contract
        if path not in cache:
            try:
                cache[path] = open(path, errors="ignore").read()
            except Exception:  # noqa: BLE001
                cache[path] = ""
        return cache[path]

    total = 0
    for key, lst in findings.items():
        if isinstance(lst, list) and lst and isinstance(lst[0], dict):
            findings[key] = ranker.rank(lst, code_for)
            total += len(lst)
    info(f"rank: ordered {total} finding(s) by P(real) — triage, recall-safe (nothing dropped)")


def _run_full_audit_with_correlation(
    contract: str,
    output: str | None,
    fmt: str,
    layer_list: list[int],
    timeout: int,
    api: Any,
    verify_fp: bool = False,
    verify_model: str | None = None,
    rank: bool = False,
    baseline_path: str | None = None,
    fail_on_new: bool = False,
) -> None:
    """Run full audit using Correlation API."""
    all_results: list[dict[str, Any]] = []
    _vfp_dropped = _vfp_flagged = 0

    for layer in layer_list:
        if layer in LAYERS:
            layer_info = LAYERS[layer]
            if RICH_AVAILABLE:
                console.print(
                    f"\n[bold cyan]=== Layer {layer}: {layer_info['name']} ===[/bold cyan]"
                )
            else:
                print(f"\n=== Layer {layer}: {layer_info['name']} ===")

            results = run_layer(layer, contract, timeout)
            if verify_fp:
                try:
                    from miesc.ml.benign_context_verifier import apply_to_results

                    d, fl = apply_to_results(results, contract=contract, model=verify_model)
                    _vfp_dropped += d
                    _vfp_flagged += fl
                except Exception:  # noqa: BLE001
                    pass
            all_results.extend(results)

            # Add to correlation API
            for result in results:
                if result.get("status") == "success" and result.get("findings"):
                    api.add_tool_results(result["tool"], result["findings"])

    if verify_fp:
        mode = f"LLM {verify_model}" if verify_model else "rule-only"
        info(
            f"verify-fp ({mode}): dropped {_vfp_dropped} benign-context FP(s), "
            f"flagged {_vfp_flagged} for review — real findings kept (recall-safe)"
        )

    # Run correlation analysis
    info("Running cross-tool correlation...")
    report = api.analyze(output_format="full")

    # Display correlated summary
    summary = report.get("summary", {})
    findings = report.get("findings", {})

    if rank:
        _rank_report_findings(findings, contract=contract)

    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Correlated Audit Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Correlated", str(summary.get("total_correlated", 0)))
        table.add_row("Cross-Validated", str(summary.get("cross_validated", 0)))
        table.add_row("High Confidence", str(summary.get("high_confidence_count", 0)))
        table.add_row("Likely FPs Filtered", str(len(findings.get("likely_false_positives", []))))
        table.add_row("Dedup Rate", f"{summary.get('deduplication_rate', 0)*100:.1f}%")
        console.print(table)

        # Actionable findings
        actionable = findings.get("actionable", [])
        if actionable:
            console.print(f"\n[bold]Top Actionable Findings ({len(actionable)}):[/bold]")
            for f in actionable[:5]:
                sev = f.get("severity", "unknown").upper()
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
                console.print(
                    f"  [{color}][{sev}][/{color}] {f.get('type', 'unknown')} - {f.get('location', {}).get('file', '')}:{f.get('location', {}).get('line', 0)}"
                )
    else:
        print("\n=== Correlated Summary ===")
        print(f"Total: {summary.get('total_correlated', 0)}")
        print(f"Cross-validated: {summary.get('cross_validated', 0)}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # Baseline suppression gate (on raw per-layer findings)
    if baseline_path:
        from miesc.cli.commands.baseline import apply_baseline_gate

        gate_findings = [f for r in all_results for f in r.get("findings", [])]
        apply_baseline_gate(gate_findings, baseline_path, fail_on_new=fail_on_new)


def _run_full_audit_basic(
    contract: str,
    output: str | None,
    fmt: str,
    layer_list: list[int],
    timeout: int,
    verify_fp: bool = False,
    verify_model: str | None = None,
    rank: bool = False,
    baseline_path: str | None = None,
    fail_on_new: bool = False,
) -> None:
    """Run full audit in basic mode (no ML/correlation)."""
    import time as _time

    all_results: list[dict[str, Any]] = []
    layer_timing: dict[int | str, float] = {}  # layer_num → elapsed_seconds

    for layer in layer_list:
        if layer in LAYERS:
            layer_info = LAYERS[layer]
            if RICH_AVAILABLE:
                console.print(
                    f"\n[bold cyan]=== Layer {layer}: {layer_info['name']} ===[/bold cyan]"
                )
                console.print(f"[dim]{layer_info['description']}[/dim]")
            else:
                print(f"\n=== Layer {layer}: {layer_info['name']} ===")

            layer_start = _time.perf_counter()
            results = run_layer(layer, contract, timeout)
            layer_elapsed = _time.perf_counter() - layer_start
            layer_timing[layer] = round(layer_elapsed, 3)

            # Tag each result with timing metadata
            for r in results:
                r["_layer"] = layer
                r["_layer_time_s"] = layer_timing[layer]

            all_results.extend(results)

    # v5.4.x: Run enabled plugin detectors
    plugin_start = _time.perf_counter()
    plugin_results = run_plugins(contract, timeout)
    if plugin_results:
        plugin_elapsed = _time.perf_counter() - plugin_start
        layer_timing["plugins"] = round(plugin_elapsed, 3)
        all_results.extend(plugin_results)
        info(f"Plugins: {len(plugin_results)} detectors executed")

    # v5.2.0: Intelligence engine — cross-tool scoring, semantic dedup,
    # zero-recall pattern detection, context-aware FP suppression,
    # LLM↔static cross-validation, severity calibration.
    try:
        from miesc.core.intelligence import enhance_findings

        all_findings_flat: list[dict[str, Any]] = []
        for result in all_results:
            for f in result.get("findings", []):
                f.setdefault("tool", result.get("tool", "unknown"))
                all_findings_flat.append(f)
        if all_findings_flat:
            try:
                code_text = Path(contract).read_text(encoding="utf-8")
            except Exception:
                code_text = ""
            enhanced = enhance_findings(
                all_findings_flat, source_code=code_text, file_path=str(contract)
            )
            non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
            suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
            # Preserve per-tool metadata for report layer coverage
            tool_metadata = [{k: v for k, v in r.items() if k != "findings"} for r in all_results]
            all_results = tool_metadata + [
                {"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}
            ]
            if suppressed_count > 0:
                info(f"Intelligence engine: suppressed {suppressed_count} likely false positives")
            deduped = len(all_findings_flat) - len(enhanced)
            if deduped > 0:
                info(f"Intelligence engine: merged {deduped} duplicate findings across tools")
    except Exception:
        pass  # graceful degradation

    # Recall-safe benign-context verifier (opt-in)
    if verify_fp:
        try:
            from miesc.ml.benign_context_verifier import apply_to_results

            dropped, flagged = apply_to_results(all_results, contract=contract, model=verify_model)
            mode = f"LLM {verify_model}" if verify_model else "rule-only"
            info(
                f"verify-fp ({mode}): dropped {dropped} benign-context FP(s), "
                f"flagged {flagged} for review — real findings kept (recall-safe)"
            )
        except Exception as e:  # noqa: BLE001
            info(f"verify-fp skipped: {e}")

    if rank:
        try:
            from miesc.ml.triage_ranker import rank_results

            n = rank_results(all_results, contract=contract)
            info(
                f"rank: ordered {n} finding(s) by P(real) — triage, recall-safe (nothing dropped)"
                if n >= 0
                else "rank: no triage model (order unchanged)"
            )
        except Exception as e:  # noqa: BLE001
            info(f"rank skipped: {e}")

    summary = summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Full Audit Summary (Basic Mode)", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)

        # Execution summary
        successful = len([r for r in all_results if r.get("status") == "success"])
        console.print(f"\n[dim]Tools executed: {successful}/{len(all_results)}[/dim]")
        console.print(
            "[yellow]Note: ML filtering disabled. Results may contain false positives.[/yellow]"
        )
    else:
        print("\n=== Full Audit Summary (Basic Mode) ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    if output:
        if fmt == "sarif":
            data: Any = _to_sarif(all_results)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
        else:
            # Normalize to scan-compatible schema for report/fix/export
            all_findings: list[dict[str, Any]] = []
            for r in all_results:
                for f in r.get("findings", []):
                    f.setdefault("tool", r.get("tool", "unknown"))
                    all_findings.append(f)
            tools_used = sorted(
                {
                    r.get("tool", "")
                    for r in all_results
                    if r.get("status") == "success" and r.get("tool")
                }
            )
            data = {
                "contract": str(contract),
                "timestamp": datetime.now().isoformat(),
                "version": VERSION,
                "success": True,
                "summary": summary,
                "total_findings": total,
                "tools": tools_used,
                "findings": all_findings,
                "results": all_results,
                "layers": layer_list,
                "ml_enabled": False,
                "timing": {
                    "per_layer": {str(k): v for k, v in layer_timing.items()},
                    "total_s": round(sum(layer_timing.values()), 3),
                },
            }

        with open(output, "w", encoding="utf-8") as f:
            if fmt == "markdown":
                f.write(data)
            else:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # Baseline suppression gate
    if baseline_path:
        from miesc.cli.commands.baseline import apply_baseline_gate

        gate_findings = [f for r in all_results for f in r.get("findings", [])]
        apply_baseline_gate(gate_findings, baseline_path, fail_on_new=fail_on_new)


# =============================================================================
# Audit Command Group
# =============================================================================


@click.group()
def audit() -> None:
    """Run security audits on smart contracts."""
    pass


@audit.command("quick")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
@click.option(
    "--verify-fp",
    is_flag=True,
    help="Recall-safe benign-context FP filter. Drops ONLY type-deterministic benign findings "
    "(Sol>=0.8 arithmetic, checked call/SafeERC20, informational lint); contextual guards and "
    "LLM judgments only FLAG (needs_review), never drop. Add --verify-model for an advisory "
    "LLM flagging pass.",
)
@click.option(
    "--verify-model",
    "verify_model",
    default=None,
    help="Ollama/DeepSeek model for an ADVISORY --verify-fp LLM pass (e.g. qwen2.5-coder:32b, "
    "deepseek): flags more suspected FPs as needs_review; never drops.",
)
@click.option(
    "--rank",
    is_flag=True,
    help="Recall-safe triage: order findings by P(real) so the most-likely-real surface "
    "first (never drops; recall 1.0). Needs a trained model (scripts/train_triage_model.py).",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(),
    default=None,
    help="Suppress findings already recorded in this baseline file "
    "(see 'miesc baseline generate').",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    help="With --baseline: exit non-zero ONLY if there are findings not in the baseline.",
)
@click.option(
    "--notify",
    "notify_url",
    type=str,
    default=None,
    help="POST a JSON scan summary to this webhook URL (SSRF-guarded; never fails the run).",
)
@click.option(
    "--slack",
    "slack_url",
    type=str,
    default=None,
    help="POST a Slack Block Kit summary to this Slack Incoming Webhook URL "
    "(SSRF-guarded; never fails the run).",
)
@click.option(
    "--notify-min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="low",
    help="Only send --notify/--slack when a finding reaches this severity (default: low).",
)
def audit_quick(
    contract: str,
    output: str | None,
    fmt: str,
    ci: bool,
    timeout: int,
    verify_fp: bool,
    verify_model: str | None,
    rank: bool,
    baseline_path: str | None,
    fail_on_new: bool,
    notify_url: str | None,
    slack_url: str | None,
    notify_min_severity: str,
) -> None:
    """Quick 3-tool scan for fast feedback (slither, aderyn, solhint)."""
    print_banner()
    info(f"Quick scan of {contract}")
    info(f"Tools: {', '.join(QUICK_TOOLS)}")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Scanning...", total=len(QUICK_TOOLS))

            for tool in QUICK_TOOLS:
                progress.update(task, description=f"Running {tool}...")
                result = run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    success(f"{tool}: {len(result.get('findings', []))} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')}")

                progress.advance(task)
    else:
        for tool in QUICK_TOOLS:
            info(f"Running {tool}...")
            result = run_tool(tool, contract, timeout)
            all_results.append(result)

    # v5.2.0: Intelligence engine — cross-tool scoring, semantic dedup,
    # zero-recall pattern detection, context-aware FP suppression,
    # LLM↔static cross-validation, severity calibration.
    try:
        from miesc.core.intelligence import enhance_findings

        all_findings_flat = []
        for result in all_results:
            for f in result.get("findings", []):
                f.setdefault("tool", result.get("tool", "unknown"))
                all_findings_flat.append(f)
        if all_findings_flat:
            try:
                code_text = open(contract).read()
            except Exception:
                code_text = ""
            enhanced = enhance_findings(
                all_findings_flat, source_code=code_text, file_path=str(contract)
            )
            non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
            suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
            # Preserve per-tool metadata for report layer coverage
            tool_metadata = [{k: v for k, v in r.items() if k != "findings"} for r in all_results]
            all_results = tool_metadata + [
                {"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}
            ]
            if suppressed_count > 0:
                info(f"Intelligence engine: suppressed {suppressed_count} likely false positives")
            deduped = len(all_findings_flat) - len(enhanced)
            if deduped > 0:
                info(f"Intelligence engine: merged {deduped} duplicate findings across tools")
    except Exception:
        pass  # graceful degradation

    # Recall-safe benign-context verifier (opt-in)
    if verify_fp:
        try:
            from miesc.ml.benign_context_verifier import apply_to_results

            dropped, flagged = apply_to_results(all_results, contract=contract, model=verify_model)
            mode = f"LLM {verify_model}" if verify_model else "rule-only"
            info(
                f"verify-fp ({mode}): dropped {dropped} benign-context FP(s), "
                f"flagged {flagged} for review — real findings kept (recall-safe)"
            )
        except Exception as e:  # noqa: BLE001
            info(f"verify-fp skipped: {e}")

    if rank:
        try:
            from miesc.ml.triage_ranker import rank_results

            n = rank_results(all_results, contract=contract)
            info(
                f"rank: ordered {n} finding(s) by P(real) — triage, recall-safe (nothing dropped)"
                if n >= 0
                else "rank: no triage model (order unchanged)"
            )
        except Exception as e:  # noqa: BLE001
            info(f"rank skipped: {e}")

    summary = summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title="Quick Scan Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print("\n=== Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data: Any = _to_sarif(all_results)
            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
        else:
            data = {"results": all_results, "summary": summary, "version": VERSION}
            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # Baseline suppression gate
    if baseline_path:
        from miesc.cli.commands.baseline import apply_baseline_gate

        gate_findings = [f for r in all_results for f in r.get("findings", [])]
        apply_baseline_gate(gate_findings, baseline_path, fail_on_new=fail_on_new)

    # Outbound notifications (webhook / Slack), fired before the CI exit.
    if notify_url or slack_url:
        from miesc.core.notifiers import dispatch_notifications

        dispatch_notifications(
            all_results,
            str(contract),
            webhook_url=notify_url,
            slack_url=slack_url,
            min_severity=notify_min_severity,
            ci_failed=(summary["CRITICAL"] > 0 or summary["HIGH"] > 0),
        )

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("full")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option(
    "--layers",
    "-l",
    type=str,
    default="1,2,3,4,5,6,7,8,9",
    help="Layers to run (comma-separated, default: all 9)",
)
@click.option("--timeout", "-t", type=int, default=600, help="Timeout per tool in seconds")
@click.option("--skip-unavailable", is_flag=True, default=True, help="Skip unavailable tools")
@click.option(
    "--ml/--no-ml", default=True, help="Enable ML pipeline for FP filtering and correlation"
)
@click.option("--correlate/--no-correlate", default=True, help="Enable cross-tool correlation")
@click.option(
    "--verify-fp",
    is_flag=True,
    help="Recall-safe benign-context FP filter. Drops ONLY type-deterministic benign findings "
    "(Sol>=0.8 arithmetic, checked call/SafeERC20, informational lint); contextual guards and "
    "LLM judgments only FLAG (needs_review), never drop. Add --verify-model for an advisory "
    "LLM flagging pass.",
)
@click.option(
    "--verify-model",
    "verify_model",
    default=None,
    help="Ollama/DeepSeek model for an ADVISORY --verify-fp LLM pass (e.g. qwen2.5-coder:32b, "
    "deepseek): flags more suspected FPs as needs_review; never drops.",
)
@click.option(
    "--rank",
    is_flag=True,
    help="Recall-safe triage: order findings by P(real) so the most-likely-real surface "
    "first (never drops; recall 1.0). Needs a trained model (scripts/train_triage_model.py).",
)
@click.option(
    "--fp-strictness",
    "fp_strictness",
    type=click.Choice(["off", "low", "medium", "high"], case_sensitive=False),
    default="off",
    help="Recall-safe benign-context FP filter applied inside the ML orchestrator "
    "(fixes issue #69). Drops ONLY type-deterministic benign findings; higher = more "
    "aggressive. Default off preserves raw recall.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(),
    default=None,
    help="Suppress findings already recorded in this baseline file "
    "(see 'miesc baseline generate').",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    help="With --baseline: exit non-zero ONLY if there are findings not in the baseline.",
)
def audit_full(
    contract: str,
    output: str | None,
    fmt: str,
    layers: str,
    timeout: int,
    skip_unavailable: bool,
    ml: bool,
    correlate: bool,
    verify_fp: bool,
    verify_model: str | None,
    rank: bool,
    fp_strictness: str,
    baseline_path: str | None,
    fail_on_new: bool,
) -> None:
    """Complete 9-layer security audit with the configured layer tools.

    By default uses ML pipeline for false positive filtering and
    cross-tool correlation for improved accuracy.

    \b
    Examples:
        miesc audit full contract.sol                    # Full audit with ML
        miesc audit full contract.sol --no-ml           # Without ML filtering
        miesc audit full contract.sol -l 1,2,3          # Only layers 1-3
        miesc audit full contract.sol -o report.json    # Save to file
    """
    print_banner()
    info(f"Full audit of {contract}")

    layer_list = [int(x.strip()) for x in layers.split(",") if x.strip().isdigit()]

    # Try to use ML Orchestrator for enhanced analysis
    ml_orchestrator = get_ml_orchestrator() if ml else None
    correlation_api = get_correlation_api() if correlate and not ml_orchestrator else None

    if ml_orchestrator:
        info(
            "[bold green]ML Pipeline enabled[/bold green] - FP filtering active"
            if RICH_AVAILABLE
            else "ML Pipeline enabled - FP filtering active"
        )
        _run_full_audit_with_ml(
            contract,
            output,
            fmt,
            layer_list,
            timeout,
            ml_orchestrator,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            fp_strictness=fp_strictness,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
        )
        return

    if correlation_api:
        info(
            "[cyan]Correlation enabled[/cyan] - Cross-tool validation active"
            if RICH_AVAILABLE
            else "Correlation enabled - Cross-tool validation active"
        )
        _run_full_audit_with_correlation(
            contract,
            output,
            fmt,
            layer_list,
            timeout,
            correlation_api,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
        )
        return

    # Fallback to basic mode
    if ml or correlate:
        warning("ML/Correlation modules not available, using basic mode")

    _run_full_audit_basic(
        contract,
        output,
        fmt,
        layer_list,
        timeout,
        verify_fp=verify_fp,
        verify_model=verify_model,
        baseline_path=baseline_path,
        fail_on_new=fail_on_new,
    )


@audit.command("layer")
@click.argument("layer_num", type=int)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
def audit_layer(layer_num: int, contract: str, output: str | None, timeout: int) -> None:
    """Run a specific layer's tools (1-9)."""
    print_banner()

    if layer_num not in LAYERS:
        error(f"Invalid layer: {layer_num}. Valid layers: {', '.join(map(str, LAYERS))}")
        for num, layer_info in LAYERS.items():
            info(f"  Layer {num}: {layer_info['name']}")
        sys.exit(1)

    layer_info = LAYERS[layer_num]
    info(f"Layer {layer_num}: {layer_info['name']}")
    info(f"Description: {layer_info['description']}")
    info(f"Tools: {', '.join(layer_info['tools'])}")

    results = run_layer(layer_num, contract, timeout)
    summary = summarize_findings(results)

    if RICH_AVAILABLE:
        table = Table(title=f"Layer {layer_num} Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev, count in summary.items():
            table.add_row(sev, str(count))
        console.print(table)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(
                {"layer": layer_num, "results": results, "summary": summary},
                f,
                indent=2,
                default=str,
            )
        success(f"Report saved to {output}")


@audit.command("smart")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown"]), default="json")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
@click.option(
    "--llm-validate/--no-llm-validate", default=False, help="Use LLM to validate findings"
)
def audit_smart(
    contract: str,
    output: str | None,
    fmt: str,
    timeout: int,
    llm_validate: bool,
) -> None:
    """Smart audit with ML filtering, correlation, and optional LLM validation.

    This is the recommended command for accurate security analysis:
    - Runs multiple tools (Slither, Aderyn, Mythril, etc.)
    - Applies ML-based false positive filtering
    - Correlates findings across tools
    - Optionally validates findings with local LLM

    \b
    Examples:
        miesc audit smart contract.sol                    # Smart audit
        miesc audit smart contract.sol --llm-validate    # With LLM validation
        miesc audit smart contract.sol -o report.json    # Save report
    """
    print_banner()
    info(f"Smart audit of {contract}")

    # Get ML orchestrator
    ml_orchestrator = get_ml_orchestrator()

    if not ml_orchestrator:
        error("ML Orchestrator not available. Please check installation.")
        info("Falling back to basic audit...")
        # Fall back to basic
        _run_full_audit_basic(contract, output, fmt, [1, 2, 3], timeout)
        return

    if RICH_AVAILABLE:
        console.print("[bold green]ML Pipeline[/bold green] enabled")
        console.print("[cyan]Cross-tool correlation[/cyan] enabled")
        if llm_validate:
            console.print("[magenta]LLM validation[/magenta] enabled")

    # Define smart tool selection (core reliable tools)
    smart_tools = ["slither", "aderyn", "mythril", "solhint"]

    info(f"Tools: {', '.join(smart_tools)}")

    # Progress display
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Analyzing...", total=100)

            def progress_callback(stage: str, message: str, pct: float) -> None:
                progress.update(task, description=message, completed=int(pct * 100))

            result = ml_orchestrator.analyze(
                contract_path=contract,
                tools=smart_tools,
                timeout=timeout,
                progress_callback=progress_callback,
            )
    else:
        result = ml_orchestrator.analyze(
            contract_path=contract,
            tools=smart_tools,
            timeout=timeout,
        )

    # Optional LLM validation
    if llm_validate and result.ml_filtered_findings:
        info("Running LLM validation on findings...")
        try:
            from miesc.llm.finding_validator import LLMFindingValidator, ValidatorConfig

            validator_config = ValidatorConfig(
                min_severity_to_validate="medium",
                timeout_seconds=60,
            )
            validator = LLMFindingValidator(validator_config)

            import asyncio

            async def validate() -> tuple[list[dict[str, Any]], list[Any]]:
                validated, validations = await validator.validate_findings_batch(
                    result.ml_filtered_findings
                )
                await validator.close()
                return validated, validations

            validated_findings, validations = asyncio.run(validate())

            # Update result with LLM validation
            llm_fp_count = len(result.ml_filtered_findings) - len(validated_findings)
            if llm_fp_count > 0:
                info(f"LLM filtered {llm_fp_count} additional false positives")
                result.ml_filtered_findings = validated_findings
                result.false_positives_removed += llm_fp_count

        except Exception as e:
            warning(f"LLM validation failed: {e}")

    # Display results
    summary = result.get_summary()

    if RICH_AVAILABLE:
        console.print("\n")

        # Risk badge
        risk_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(summary["risk_level"], "white")
        console.print(
            Panel(
                f"[bold {risk_color}]{summary['risk_level']}[/bold {risk_color}]",
                title="Risk Level",
                border_style=risk_color,
            )
        )

        # Summary table
        table = Table(title="Smart Audit Results", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Critical", f"[red]{summary['critical']}[/red]")
        table.add_row("High", f"[red]{summary['high']}[/red]")
        table.add_row("Medium", f"[yellow]{summary['medium']}[/yellow]")
        table.add_row("Low", f"[cyan]{summary['low']}[/cyan]")
        table.add_row("Total", f"[bold]{summary['total_findings']}[/bold]")
        console.print(table)

        # Effectiveness metrics
        console.print(f"\n[dim]Raw findings: {result.total_raw_findings}[/dim]")
        console.print(
            f"[green]FPs removed: {result.false_positives_removed} ({summary['reduction_rate']:.1f}% reduction)[/green]"
        )
        console.print(f"[dim]Cross-validated: {result.cross_validated}[/dim]")

        # Top findings
        if result.ml_filtered_findings:
            console.print("\n[bold]Top Findings:[/bold]")
            for f in result.ml_filtered_findings[:5]:
                sev = f.get("severity", "unknown").upper()
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "cyan")
                vtype = f.get("type", f.get("title", "unknown"))
                loc = f.get("location", {})
                console.print(
                    f"  [{color}][{sev}][/{color}] {vtype} - {loc.get('file', '')}:{loc.get('line', 0)}"
                )
    else:
        print("\n=== Smart Audit Results ===")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Total: {summary['total_findings']}")
        print(f"Critical: {summary['critical']}, High: {summary['high']}")
        print(f"FPs removed: {result.false_positives_removed}")

    # Save output
    if output:
        if fmt == "json":
            data = result.to_dict()
            data["llm_validated"] = llm_validate
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        else:
            md = _ml_result_to_markdown(result, contract)
            with open(output, "w", encoding="utf-8") as f:
                f.write(md)
        success(f"Report saved to {output}")


@audit.command("profile")
@click.argument("profile_name", type=str)
@click.argument("contract", type=click.Path(exists=True), required=False)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
def audit_profile(
    profile_name: str,
    contract: str | None,
    output: str | None,
    fmt: str,
    ci: bool,
) -> None:
    """Run audit using a predefined profile (fast, balanced, thorough, security, ci, audit, defi, token)."""
    print_banner()

    # List profiles
    if profile_name == "list":
        profiles = load_profiles()
        if RICH_AVAILABLE:
            table = Table(title="Available Profiles", box=box.ROUNDED)
            table.add_column("Profile", style="bold cyan")
            table.add_column("Description")
            table.add_column("Layers")
            table.add_column("Timeout")

            for name, profile in profiles.items():
                layers_str = ", ".join(str(layer) for layer in profile.get("layers", []))
                table.add_row(
                    name,
                    profile.get("description", "")[:50],
                    layers_str,
                    f"{profile.get('timeout', 300)}s",
                )
            console.print(table)
        else:
            for name, profile in profiles.items():
                print(f"\n{name}: {profile.get('description', '')}")
                print(f"  Layers: {profile.get('layers', [])}")
                print(f"  Timeout: {profile.get('timeout', 300)}s")
        return

    if not contract:
        error("Contract path is required when running a profile")
        sys.exit(1)

    # Get profile configuration
    profile = get_profile(profile_name)
    if not profile:
        error(f"Profile '{profile_name}' not found")
        info(f"Available profiles: {', '.join(AVAILABLE_PROFILES)}")
        sys.exit(1)

    info(f"Running profile: {profile_name}")
    info(f"Description: {profile.get('description', 'N/A')}")

    if _profile_uses_agentic_path(profile):
        _run_agentic_audit_profile(profile_name, profile, contract, output, fmt, ci)
        return

    # Extract profile settings
    layers = profile.get("layers", [1])
    timeout = profile.get("timeout", 300)
    tools_config = profile.get("tools", [])

    if tools_config == "all":
        # Use all tools from specified layers
        tools_to_run = []
        for layer in layers:
            if layer in LAYERS:
                tools_to_run.extend(LAYERS[layer]["tools"])
    elif isinstance(tools_config, list):
        tools_to_run = tools_config
    else:
        tools_to_run = QUICK_TOOLS

    info(f"Layers: {layers}")
    info(f"Tools: {', '.join(tools_to_run[:5])}{'...' if len(tools_to_run) > 5 else ''}")
    info(f"Timeout: {timeout}s per tool")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(tools_to_run))

            for tool in tools_to_run:
                progress.update(task, description=f"Running {tool}...")
                result = run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    findings_count = len(result.get("findings", []))
                    success(f"{tool}: {findings_count} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')[:50]}")

                progress.advance(task)
    else:
        for tool in tools_to_run:
            info(f"Running {tool}...")
            result = run_tool(tool, contract, timeout)
            all_results.append(result)

    # v5.2.0: Intelligence engine — cross-tool scoring, semantic dedup,
    # zero-recall pattern detection, context-aware FP suppression,
    # LLM↔static cross-validation, severity calibration.
    try:
        from miesc.core.intelligence import enhance_findings

        all_findings_flat = []
        for result in all_results:
            for f in result.get("findings", []):
                f.setdefault("tool", result.get("tool", "unknown"))
                all_findings_flat.append(f)
        if all_findings_flat:
            try:
                code_text = open(contract).read()
            except Exception:
                code_text = ""
            enhanced = enhance_findings(
                all_findings_flat, source_code=code_text, file_path=str(contract)
            )
            non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
            suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
            # Preserve per-tool metadata for report layer coverage
            tool_metadata = [{k: v for k, v in r.items() if k != "findings"} for r in all_results]
            all_results = tool_metadata + [
                {"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}
            ]
            if suppressed_count > 0:
                info(f"Intelligence engine: suppressed {suppressed_count} likely false positives")
            deduped = len(all_findings_flat) - len(enhanced)
            if deduped > 0:
                info(f"Intelligence engine: merged {deduped} duplicate findings across tools")
    except Exception:
        pass  # graceful degradation

    summary = summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title=f"{profile_name.upper()} Profile Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print(f"\n=== {profile_name.upper()} Profile Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data: Any = _to_sarif(all_results)
            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
        else:
            data = {
                "profile": profile_name,
                "results": all_results,
                "summary": summary,
                "version": VERSION,
            }
            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("single")
@click.argument("tool", type=str)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout in seconds")
def audit_single(tool: str, contract: str, output: str | None, timeout: int) -> None:
    """Run a single security tool."""
    print_banner()

    # Validate tool exists
    all_tools = list(ADAPTER_MAP.keys())

    if tool not in all_tools:
        error(f"Unknown tool: {tool}")
        info(f"Available tools: {', '.join(all_tools)}")
        sys.exit(1)

    info(f"Running {tool} on {contract}")

    result = run_tool(tool, contract, timeout)

    if result["status"] == "success":
        findings_count = len(result.get("findings", []))
        success(f"{findings_count} findings in {result.get('execution_time', 0):.1f}s")

        if RICH_AVAILABLE and result.get("findings"):
            table = Table(title=f"{tool.upper()} Findings", box=box.ROUNDED)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=40)
            table.add_column("Location", width=30)

            for finding in result["findings"][:20]:
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_str = f"{location.get('file', '')}:{location.get('line', 0)}"
                else:
                    loc_str = str(location)

                table.add_row(
                    str(finding.get("severity", "INFO")),
                    str(finding.get("title", finding.get("type", finding.get("id", ""))))[:40],
                    loc_str[:30],
                )

            if len(result["findings"]) > 20:
                table.add_row("...", f"({len(result['findings']) - 20} more)", "")

            console.print(table)
    else:
        error(f"Failed: {result.get('error', 'Unknown error')}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        success(f"Report saved to {output}")


@audit.command("batch")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown", "csv"]), default="json"
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "fast", "balanced", "thorough"]),
    default="quick",
    help="Analysis profile",
)
@click.option("--parallel", "-j", type=int, default=4, help="Number of parallel workers")
@click.option("--recursive", "-r", is_flag=True, help="Recursively search for .sol files")
@click.option("--pattern", type=str, default="*.sol", help="File pattern to match")
@click.option(
    "--fail-on", type=str, default="", help="Fail on severity (comma-separated: critical,high)"
)
def audit_batch(
    path: str,
    output: str | None,
    fmt: str,
    profile: str,
    parallel: int,
    recursive: bool,
    pattern: str,
    fail_on: str,
) -> None:
    """Batch analysis of multiple contracts.

    Analyze all .sol files in a directory with parallel execution.
    Aggregates results into a single comprehensive report.

    Examples:
      miesc audit batch ./contracts                     # Scan all contracts
      miesc audit batch ./src -r --profile balanced    # Recursive with balanced profile
      miesc audit batch . -j 8 -o report.json          # 8 parallel workers
      miesc audit batch ./contracts --fail-on critical,high  # CI mode
    """
    print_banner()

    # Find all Solidity files
    path_obj = Path(path)

    if path_obj.is_file():
        if path_obj.suffix == ".sol":
            sol_files = [str(path_obj)]
        else:
            error(f"Not a Solidity file: {path}")
            sys.exit(1)
    else:
        if recursive:
            sol_files = list(glob_module.glob(str(path_obj / "**" / pattern), recursive=True))
        else:
            sol_files = list(glob_module.glob(str(path_obj / pattern)))

    if not sol_files:
        warning(f"No {pattern} files found in {path}")
        sys.exit(0)

    info(f"Found {len(sol_files)} Solidity files")
    info(f"Profile: {profile} | Workers: {parallel}")

    # Select tools based on profile
    profile_tools = {
        "quick": QUICK_TOOLS,
        "fast": ["slither", "aderyn"],
        "balanced": ["slither", "aderyn", "solhint", "mythril"],
        "thorough": QUICK_TOOLS + ["echidna", "medusa"],
    }
    tools_to_run = profile_tools.get(profile, QUICK_TOOLS)
    info(f"Tools: {', '.join(tools_to_run)}")

    # Results storage
    all_contract_results = []
    aggregated_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    failed_contracts = []
    start_time = datetime.now()

    def analyze_contract(contract_path: str) -> Dict[str, Any]:
        """Analyze a single contract with all tools."""
        contract_results = []
        for tool in tools_to_run:
            result = run_tool(tool, contract_path, timeout=120)
            contract_results.append(result)

        summary = summarize_findings(contract_results)
        return {
            "contract": contract_path,
            "results": contract_results,
            "summary": summary,
            "total_findings": sum(summary.values()),
        }

    # Progress display
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        ) as progress:
            task = progress.add_task("Analyzing contracts...", total=len(sol_files))

            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

                for future in concurrent.futures.as_completed(future_to_contract):
                    contract = future_to_contract[future]
                    try:
                        result = future.result()
                        all_contract_results.append(result)

                        # Update aggregated summary
                        for sev, count in result["summary"].items():
                            aggregated_summary[sev] += count

                        # Show individual result
                        contract_name = Path(contract).name
                        findings = result["total_findings"]
                        crit = result["summary"]["CRITICAL"]
                        high = result["summary"]["HIGH"]

                        if crit > 0 or high > 0:
                            console.print(
                                f"  [red]{contract_name}[/red]: "
                                f"{crit} critical, {high} high, {findings} total"
                            )
                        elif findings > 0:
                            console.print(
                                f"  [yellow]{contract_name}[/yellow]: {findings} findings"
                            )

                    except Exception as e:
                        failed_contracts.append({"contract": contract, "error": str(e)})
                        console.print(f"  [red]{Path(contract).name}[/red]: error - {e}")

                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

            completed = 0
            for future in concurrent.futures.as_completed(future_to_contract):
                contract = future_to_contract[future]
                completed += 1
                print(f"[{completed}/{len(sol_files)}] Processing {Path(contract).name}...")

                try:
                    result = future.result()
                    all_contract_results.append(result)

                    for sev, count in result["summary"].items():
                        aggregated_summary[sev] += count

                except Exception as e:
                    failed_contracts.append({"contract": contract, "error": str(e)})
                    print(f"  Error: {e}")

    elapsed = (datetime.now() - start_time).total_seconds()
    total_findings = sum(aggregated_summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Batch Analysis Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Contracts Analyzed", str(len(all_contract_results)))
        table.add_row("Failed", str(len(failed_contracts)))
        table.add_row("Execution Time", f"{elapsed:.1f}s")
        table.add_row("", "")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in aggregated_summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))

        table.add_row("TOTAL FINDINGS", str(total_findings), style="bold")
        console.print(table)

        # Show most vulnerable contracts
        sorted_contracts = sorted(
            all_contract_results,
            key=lambda x: (x["summary"]["CRITICAL"], x["summary"]["HIGH"], x["total_findings"]),
            reverse=True,
        )

        if sorted_contracts and total_findings > 0:
            console.print("\n[bold]Top Vulnerable Contracts:[/bold]")
            for result in sorted_contracts[:5]:
                if result["total_findings"] > 0:
                    console.print(
                        f"  {Path(result['contract']).name}: "
                        f"C:{result['summary']['CRITICAL']} H:{result['summary']['HIGH']} "
                        f"M:{result['summary']['MEDIUM']} L:{result['summary']['LOW']}"
                    )
    else:
        print("\n=== Batch Analysis Summary ===")
        print(f"Contracts: {len(all_contract_results)}")
        print(f"Failed: {len(failed_contracts)}")
        print(f"Time: {elapsed:.1f}s")
        print("\nFindings by severity:")
        for sev, count in aggregated_summary.items():
            print(f"  {sev}: {count}")
        print(f"  TOTAL: {total_findings}")

    # Build output data
    output_data = {
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "execution_time": elapsed,
        "profile": profile,
        "path": str(path),
        "contracts_analyzed": len(all_contract_results),
        "contracts_failed": len(failed_contracts),
        "aggregated_summary": aggregated_summary,
        "total_findings": total_findings,
        "contracts": all_contract_results,
        "failed": failed_contracts,
    }

    # Save output
    if output:
        if fmt == "sarif":
            # Flatten all results for SARIF
            all_results = []
            for contract_data in all_contract_results:
                for result in contract_data.get("results", []):
                    result["contract"] = contract_data["contract"]
                    all_results.append(result)
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            # Generate batch markdown report
            sorted_contracts = sorted(
                all_contract_results,
                key=lambda x: (x["summary"]["CRITICAL"], x["summary"]["HIGH"], x["total_findings"]),
                reverse=True,
            )
            md = f"""# MIESC Batch Security Audit Report

**Path**: `{path}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}
**Profile**: {profile}

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts Analyzed | {len(all_contract_results)} |
| Contracts Failed | {len(failed_contracts)} |
| Execution Time | {elapsed:.1f}s |

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {aggregated_summary['CRITICAL']} |
| High | {aggregated_summary['HIGH']} |
| Medium | {aggregated_summary['MEDIUM']} |
| Low | {aggregated_summary['LOW']} |
| Info | {aggregated_summary['INFO']} |
| **Total** | **{total_findings}** |

## Contract Analysis

"""
            for contract_data in sorted_contracts:
                contract_name = Path(contract_data["contract"]).name
                summary = contract_data["summary"]
                md += f"""### {contract_name}

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |

"""
            md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"
            with open(output, "w") as f:
                f.write(md)
        elif fmt == "csv":
            import csv

            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Contract", "Tool", "Severity", "Title", "Description", "Line"])
                for contract_data in all_contract_results:
                    for result in contract_data.get("results", []):
                        for finding in result.get("findings", []):
                            location = finding.get("location", {})
                            if isinstance(location, dict):
                                line = location.get("line", 0)
                            else:
                                line = 0
                            writer.writerow(
                                [
                                    Path(contract_data["contract"]).name,
                                    result.get("tool", ""),
                                    finding.get("severity", ""),
                                    finding.get("title", finding.get("type", ""))[:50],
                                    finding.get("description", finding.get("message", ""))[:100],
                                    line,
                                ]
                            )
        else:  # json
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

        success(f"Report saved to {output}")

    # Fail-on check for CI
    if fail_on:
        severities = [s.strip().upper() for s in fail_on.split(",")]
        for sev in severities:
            if sev in aggregated_summary and aggregated_summary[sev] > 0:
                error(f"Found {aggregated_summary[sev]} {sev} issues (fail-on: {fail_on})")
                sys.exit(1)

    success(
        f"Batch analysis complete: {len(all_contract_results)} contracts, {total_findings} findings"
    )


@audit.command("deep")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown"]), default="json")
@click.option("--timeout", "-t", type=int, default=600, help="Max total audit time in seconds")
@click.option("--max-iterations", type=int, default=5, help="Max agentic loop iterations")
@click.option("--profile", type=str, help="Apply a configured deep audit profile")
@click.option("--no-llm", is_flag=True, help="Disable LLM synthesis entirely")
@click.option("--no-rag", is_flag=True, help="Disable RAG enrichment")
@click.option(
    "--llm-provider",
    type=click.Choice(["auto", "ollama", "anthropic", "openai"]),
    default="auto",
    help="LLM provider: auto (local-first with cloud fallback), ollama, anthropic, openai",
)
@click.option("--ci", is_flag=True, help="CI mode: exit 1 if critical/high issues")
def audit_deep(
    contract: str,
    output: str | None,
    fmt: str,
    timeout: int,
    max_iterations: int,
    profile: str | None,
    no_llm: bool,
    no_rag: bool,
    llm_provider: str,
    ci: bool,
) -> None:
    """Agentic deep audit with iterative analysis and cross-layer correlation.

    \b
    This is the most thorough analysis mode. It:
    - Analyzes contract structure (call graph, taint sources)
    - Selects tools based on risk profile (not run-all)
    - Iteratively investigates HIGH/CRITICAL findings
    - Enriches findings with RAG vulnerability knowledge
    - Detects exploit chains across findings
    - Generates LLM narrative (local Ollama, optional)
    - 100% local execution, DPGA compliant

    \b
    Examples:
        miesc audit deep contract.sol
        miesc audit deep contract.sol --no-llm
        miesc audit deep contract.sol -t 300
        miesc audit deep contract.sol -o report.json --ci
    """
    print_banner()

    from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

    config = DeepAuditConfig(
        timeout_seconds=timeout,
        max_iterations=max_iterations,
        enable_llm=not no_llm,
        llm_provider=llm_provider,
        enable_rag=not no_rag,
    )
    profile_config: Dict[str, Any]
    config, profile_config = _apply_deep_profile_config(config, profile)

    agent = DeepAuditAgent(config=config)

    info(f"Starting agentic deep audit on {contract}")
    llm_status = f"{config.llm_provider}" if config.enable_llm else "disabled"
    info(
        f"Timeout: {config.timeout_seconds}s | Max iterations: {config.max_iterations} | "
        f"LLM: {llm_status} | RAG: {config.enable_rag}"
    )
    if profile:
        info(f"Profile: {profile} | {profile_config.get('description', '')}")

    if RICH_AVAILABLE:
        from rich.progress import Progress, SpinnerColumn, TextColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running agentic deep audit...", total=None)
            result = agent.analyze(contract)
            progress.update(task, description="Deep audit complete")
    else:
        result = agent.analyze(contract)

    # Display results
    summary = result.get("summary", {})
    phases = result.get("phases", {})

    if RICH_AVAILABLE:
        from rich.panel import Panel
        from rich.table import Table

        # Risk profile
        recon = phases.get("reconnaissance", {})
        profile = recon.get("risk_profile", {})
        console.print(
            Panel(
                f"[bold]{profile.get('primary', 'general').upper()}[/bold]",
                title="Risk Profile",
                border_style="cyan",
            )
        )

        # Phase summary
        inv = phases.get("deep_investigation", {})
        console.print(f"\n  Iterations: {inv.get('iterations', 0)}")
        console.print(f"  Findings enriched: {inv.get('findings_enriched', 0)}")
        console.print(f"  Exploit chains: {inv.get('chains_detected', 0)}")
        console.print(f"  Mitigated: {inv.get('mitigated', 0)}")
        if inv.get("additional_tools"):
            console.print(f"  Additional tools triggered: {inv['additional_tools']}")

        # Findings table
        table = Table(title="Deep Audit Results")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary.get(sev, 0)
            style = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else ""
            table.add_row(sev, str(count), style=style)
        table.add_row("TOTAL", str(summary.get("total", 0)), style="bold")
        console.print(table)

    # Narrative
    narrative = result.get("narrative", "")
    if narrative:
        info("Executive narrative:")
        click.echo(narrative[:500])

    # Save output
    if output:
        import json as json_mod

        output_path = Path(output)
        if fmt == "json":
            output_path.write_text(json_mod.dumps(result, indent=2, default=str))
        else:
            # Markdown summary
            md = f"# Deep Audit Report\n\n{narrative}\n\n"
            md += "## Summary\n\n| Severity | Count |\n|---|---|\n"
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                md += f"| {sev} | {summary.get(sev, 0)} |\n"
            md += f"\nTools used: {', '.join(summary.get('tools_used', []))}\n"
            md += f"Iterations: {summary.get('iterations', 0)}\n"
            md += f"Exploit chains: {summary.get('exploit_chains', 0)}\n"
            output_path.write_text(md)
        success(f"Report saved to {output}")

    # CI mode
    if ci:
        critical = summary.get("CRITICAL", 0)
        high = summary.get("HIGH", 0)
        if critical > 0 or high > 0:
            error(f"CI check failed: {critical} critical, {high} high issues")
            sys.exit(1)

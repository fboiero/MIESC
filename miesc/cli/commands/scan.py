"""
MIESC CLI - Scan Command

Simplified entry point for quick vulnerability scanning.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click

from miesc import __version__ as VERSION
from miesc.cli.constants import QUICK_TOOLS
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    get_max_workers,
    get_profile,
    info,
    print_banner,
    run_tool,
    success,
    summarize_findings,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table


# =============================================================================
# Scan Command
# =============================================================================


@click.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option("--profile", type=str, help="Apply a configured scan/audit profile")
@click.option("--ci", is_flag=True, help="CI mode: exit 1 if critical/high issues found")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output, only show summary")
@click.option(
    "--fp-strictness",
    type=click.Choice(["off", "low", "medium", "high"], case_sensitive=False),
    default="medium",
    help="False positive filter strictness: off=report everything, low=permissive, medium=balanced (default), high=aggressive for CI",
)
@click.option(
    "--llm-enhance",
    is_flag=True,
    help="Enhance top findings with AI insights (adds ~40s, requires Ollama)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show confidence scores + remediation per finding",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan subdirectories when CONTRACT is a directory",
)
@click.option(
    "--diff",
    "diff_ref",
    default=None,
    help="Only scan .sol files changed since this git ref (e.g., HEAD~1, main)",
)
@click.option(
    "--model",
    "frontier_model",
    type=click.Choice(
        [
            "claude",
            "gpt",
            "claude-opus",
            "claude-sonnet",
            "gpt-4o",
            "gpt-4.1",
            "gpt-5",
            "deepseek-v4-pro",
            "deepseek-v4-flash",
            "ollama",
            "qwen32b",
            "qwen14b",
            "codellama",
        ],
        case_sensitive=False,
    ),
    default=None,
    help="Use frontier LLM for deep semantic analysis (requires API key)",
)
@click.option(
    "--deep",
    is_flag=True,
    help="Multi-pass analysis: second pass targets functions from first pass (2x cost, higher recall)",
)
@click.option(
    "--ensemble",
    is_flag=True,
    help="Multi-provider ensemble: runs Claude + GPT-4o + Ollama local, merges findings (highest recall)",
)
@click.option(
    "--verify-fp",
    is_flag=True,
    help="Recall-safe benign-context verifier. Drops ONLY type-deterministic benign findings "
    "(Sol>=0.8 arithmetic, checked call/SafeERC20/reverting transfer, informational lint); "
    "contextual guards (onlyOwner, nonReentrant, CEI, timelock) and LLM judgments only FLAG "
    "(needs_review), never drop. Recall 1.0 validated on six sources. --verify-model adds an "
    "advisory LLM flagging pass.",
)
@click.option(
    "--verify-model",
    "verify_model",
    default=None,
    help="Ollama model for an ADVISORY --verify-fp LLM pass (e.g. qwen2.5-coder:32b): flags "
    "more suspected FPs as needs_review; never drops (no recall impact). Slower; omit for "
    "the fast rule-only verifier.",
)
@click.option(
    "--rank",
    is_flag=True,
    help="Recall-safe triage: order findings by P(real) so the most-likely-real surface "
    "first (never drops anything; recall 1.0). Needs a trained model "
    "(scripts/train_triage_model.py); no-ops gracefully without one.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(),
    default=None,
    help="Suppress findings already recorded in this baseline file "
    "(see 'miesc baseline generate'). Reports new/known/fixed counts.",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    help="With --baseline: exit non-zero ONLY if there are findings not in the baseline "
    "(CI gate for newly introduced issues).",
)
@click.option(
    "--annotate",
    type=click.Choice(["github"], case_sensitive=False),
    default=None,
    help="Emit per-finding inline annotations for a CI provider. 'github' prints "
    "GitHub Actions workflow commands (::error/::warning ...) so findings render "
    "inline on the PR diff. With --baseline, only new findings are annotated.",
)
@click.option(
    "--notify",
    "notify_url",
    type=str,
    default=None,
    help="POST a JSON scan summary (severity counts, pass/fail, top findings) to "
    "this webhook URL. SSRF-guarded; network errors never fail the scan.",
)
@click.option(
    "--slack",
    "slack_url",
    type=str,
    default=None,
    help="POST a Slack Block Kit summary to this Slack Incoming Webhook URL. "
    "SSRF-guarded; network errors never fail the scan.",
)
@click.option(
    "--notify-min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="low",
    help="Only send --notify/--slack when at least one finding reaches this "
    "severity (default: low).",
)
def scan(
    contract: str,
    output: str | None,
    profile: str | None,
    ci: bool,
    quiet: bool,
    fp_strictness: str,
    llm_enhance: bool,
    verbose: bool,
    recursive: bool,
    diff_ref: str | None,
    frontier_model: str | None,
    deep: bool,
    ensemble: bool,
    verify_fp: bool,
    verify_model: str | None,
    rank: bool,
    baseline_path: str | None,
    fail_on_new: bool,
    annotate: str | None,
    notify_url: str | None,
    slack_url: str | None,
    notify_min_severity: str,
) -> None:
    """Quick vulnerability scan for a Solidity contract or directory.

    CONTRACT can be a single .sol file or a directory containing .sol files.
    When a directory is provided, all .sol files are scanned and findings are
    aggregated. Use --recursive to also scan subdirectories.

    Use --diff to scan only files changed relative to a git ref — ideal for CI
    on pull requests: miesc scan . --diff origin/main

    This is a simplified command for quick scans. For more options,
    use 'miesc audit quick' or 'miesc audit full'.

    \b
    Examples:
        miesc scan MyContract.sol
        miesc scan contracts/
        miesc scan contracts/ --recursive
        miesc scan contracts/ --diff origin/main
        miesc scan contracts/Token.sol --ci --fp-strictness high
        miesc scan MyContract.sol --fp-strictness off -o full_report.json
        miesc scan MyContract.sol --llm-enhance -o report.json

    \b
    Exit codes:
        0 - Success (no critical/high issues, or CI mode disabled)
        1 - Critical or high severity issues found (CI mode only)
    """
    profile_config = _get_scan_profile(profile)
    profile_tools = _profile_tools(profile_config)

    # -------------------------------------------------------------------------
    # --diff mode: restrict scan to .sol files changed since diff_ref
    # -------------------------------------------------------------------------
    if diff_ref is not None:
        import subprocess

        contract_path = Path(contract)
        cwd = contract_path if contract_path.is_dir() else contract_path.parent

        try:
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", diff_ref, "--", "*.sol"],
                capture_output=True,
                text=True,
                cwd=str(cwd),
            )
            changed_names = [
                line.strip() for line in diff_result.stdout.splitlines() if line.strip()
            ]
        except Exception as exc:
            error(f"git diff failed: {exc}")
            sys.exit(1)

        # Resolve paths relative to cwd (git outputs paths relative to repo root)
        import subprocess as _sp

        try:
            repo_root_result = _sp.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                cwd=str(cwd),
            )
            repo_root = Path(repo_root_result.stdout.strip())
        except Exception:
            repo_root = cwd

        sol_files = []
        for name in changed_names:
            candidate = repo_root / name
            if candidate.suffix == ".sol" and candidate.exists():
                sol_files.append(candidate)

        if not sol_files:
            info(f"No Solidity files changed since {diff_ref}")
            sys.exit(0)

        if not quiet:
            print_banner()
            info(f"Diff scan against {diff_ref!r}: {len(sol_files)} changed .sol file(s)")

        diff_results: list[dict[str, Any]] = []
        for sol_file in sol_files:
            if not quiet:
                info(f"  → {sol_file}")
            _scan_single_file(
                str(sol_file),
                diff_results,
                quiet=quiet,
                llm_enhance=llm_enhance,
                tools=profile_tools,
            )

        for result in diff_results:
            for finding in result.get("findings", []):
                finding.setdefault("file", result.get("contract", str(contract)))

        _display_and_save(
            diff_results,
            contract=str(contract),
            output=output,
            quiet=quiet,
            verbose=verbose,
            ci=ci,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
            annotate=annotate,
            notify_url=notify_url,
            slack_url=slack_url,
            notify_min_severity=notify_min_severity,
        )
        return

    contract_path = Path(contract)

    if profile_config and _profile_uses_agentic_path(profile_config):
        if contract_path.is_dir():
            error("Agentic scan profiles currently require a single Solidity file")
            sys.exit(1)
        _run_agentic_scan_profile(
            profile or "",
            profile_config,
            contract,
            output=output,
            quiet=quiet,
            verbose=verbose,
            ci=ci,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
            annotate=annotate,
            notify_url=notify_url,
            slack_url=slack_url,
            notify_min_severity=notify_min_severity,
        )
        return

    # -------------------------------------------------------------------------
    # Directory mode: collect all .sol files and aggregate results
    # -------------------------------------------------------------------------
    if contract_path.is_dir():
        glob_pattern = "**/*.sol" if recursive else "*.sol"
        sol_files = sorted(contract_path.glob(glob_pattern))

        if not sol_files:
            error(f"No .sol files found in {contract}" + (" (recursively)" if recursive else ""))
            sys.exit(1)

        if not quiet:
            print_banner()
            info(f"Scanning directory: {contract}")
            info(f"Found {len(sol_files)} Solidity file(s)")
            info(f"Tools: {', '.join(profile_tools)}")

        all_results: list[dict[str, Any]] = []
        for sol_file in sol_files:
            if not quiet:
                info(f"  → {sol_file.name}")
            _scan_single_file(
                str(sol_file),
                all_results,
                quiet=quiet,
                llm_enhance=llm_enhance,
                tools=profile_tools,
            )

        # Tag each finding with its source file
        for result in all_results:
            for finding in result.get("findings", []):
                finding.setdefault("file", result.get("contract", str(contract)))

        # FP filter across all aggregated results (per-file code context)
        if fp_strictness.lower() != "off":
            try:
                from miesc.ml.fp_filter import FalsePositiveFilter

                fp_filter = FalsePositiveFilter(strictness=fp_strictness.lower(), use_rag=False)
                filtered_count = 0
                for result in all_results:
                    file_path = result.get("contract", "")
                    try:
                        code = Path(file_path).read_text(encoding="utf-8") if file_path else ""
                    except Exception:
                        code = ""
                    kept = []
                    for finding in result.get("findings", []):
                        fr = fp_filter.filter_finding(
                            finding, code_context=code, file_path=file_path
                        )
                        if not fr.is_likely_fp:
                            kept.append(finding)
                        else:
                            filtered_count += 1
                    result["findings"] = kept
                if not quiet and filtered_count > 0:
                    info(
                        f"FP filter ({fp_strictness}): removed {filtered_count} likely false positives"
                    )
            except Exception as e:
                if not quiet:
                    info(f"FP filter skipped: {e}")

        # Intelligence engine on aggregated findings
        try:
            from miesc.core.intelligence import enhance_findings

            all_findings_flat: list[dict[str, Any]] = []
            for result in all_results:
                for f in result.get("findings", []):
                    f.setdefault("tool", result.get("tool", "unknown"))
                    all_findings_flat.append(f)
            if all_findings_flat:
                enhanced = enhance_findings(
                    all_findings_flat,
                    source_code="",
                    file_path=str(contract),
                )
                non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
                suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
                all_results = [
                    {"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}
                ]
                if not quiet and suppressed_count > 0:
                    info(
                        f"Intelligence engine: suppressed {suppressed_count} likely false positives"
                    )
                if not quiet and len(non_suppressed) < len(all_findings_flat):
                    deduped = len(all_findings_flat) - len(enhanced)
                    if deduped > 0:
                        info(
                            f"Intelligence engine: merged {deduped} duplicate findings across tools"
                        )
        except Exception as e:
            if not quiet:
                info(f"Intelligence engine skipped: {e}")

        # Frontier LLM in directory mode: concatenate top source files
        if frontier_model:
            try:
                from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
                from miesc.core.tool_protocol import ToolStatus

                provider_map = {
                    "claude": ("anthropic", "claude-sonnet-4-6"),
                    "claude-opus": ("anthropic", "claude-opus-4-6"),
                    "claude-sonnet": ("anthropic", "claude-sonnet-4-6"),
                    "gpt": ("openai", "gpt-4o"),
                    "gpt-4o": ("openai", "gpt-4o"),
                    "gpt-4.1": ("openai", "gpt-4.1"),
                    "gpt-5": ("openai", "gpt-5"),
                    # DeepSeek V4 is OpenAI-compatible; routed via the OpenAI
                    # client pointed at the DeepSeek endpoint (see env setup below).
                    "deepseek-v4-pro": ("openai", "deepseek-v4-pro"),
                    "deepseek-v4-flash": ("openai", "deepseek-v4-flash"),
                    "ollama": ("ollama", "qwen2.5-coder:32b"),
                    "qwen32b": ("ollama", "qwen2.5-coder:32b"),
                    "qwen14b": ("ollama", "qwen2.5-coder:14b"),
                    "codellama": ("ollama", "codellama:13b"),
                }
                provider, model_id = provider_map.get(frontier_model.lower(), ("auto", None))
                # DeepSeek exposes an OpenAI-compatible API. Point the OpenAI
                # client at the DeepSeek endpoint using DEEPSEEK_API_KEY so the
                # existing openai code path sends the deepseek-v4 model name.
                if frontier_model.lower().startswith("deepseek") and os.environ.get(
                    "DEEPSEEK_API_KEY"
                ):
                    os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
                    os.environ["OPENAI_BASE_URL"] = os.environ.get(
                        "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
                    )
                adapter = FrontierLLMAdapter(provider=provider)

                if adapter.is_available() == ToolStatus.AVAILABLE:
                    if not quiet:
                        info(f"Running frontier LLM on directory ({frontier_model})...")
                    # Concat top source files up to 100KB
                    import tempfile as _tf

                    impl_files = [f for f in sol_files if not f.name.startswith("I")]
                    if not impl_files:
                        impl_files = list(sol_files)
                    impl_files.sort(key=lambda f: f.stat().st_size, reverse=True)

                    concat = _tf.NamedTemporaryFile(suffix=".sol", delete=False, mode="w")
                    total_written = 0
                    for sf in impl_files:
                        content = sf.read_text(encoding="utf-8")
                        if total_written + len(content) > 100_000 and total_written > 0:
                            break
                        concat.write(f"// ===== FILE: {sf.name} =====\n{content}\n\n")
                        total_written += len(content)
                    concat.close()

                    kwargs: dict[str, Any] = {"model": model_id} if model_id else {}
                    if deep:
                        kwargs["deep"] = True
                    frontier_result = adapter.analyze(concat.name, **kwargs)
                    Path(concat.name).unlink(missing_ok=True)

                    if frontier_result.get("status") == "success":
                        frontier_findings = frontier_result.get("findings", [])
                        if not quiet:
                            info(f"Frontier LLM found {len(frontier_findings)} findings")
                        all_results.append(frontier_result)
            except Exception as e:
                if not quiet:
                    info(f"Frontier LLM skipped: {e}")

        _display_and_save(
            all_results,
            contract=str(contract),
            output=output,
            quiet=quiet,
            verbose=verbose,
            ci=ci,
            verify_fp=verify_fp,
            verify_model=verify_model,
            rank=rank,
            baseline_path=baseline_path,
            fail_on_new=fail_on_new,
            annotate=annotate,
            notify_url=notify_url,
            slack_url=slack_url,
            notify_min_severity=notify_min_severity,
        )
        return

    # -------------------------------------------------------------------------
    # Single-file mode (original behavior — unchanged)
    # -------------------------------------------------------------------------
    if not quiet:
        print_banner()
        info(f"Scanning {contract}")
        info(f"Tools: {', '.join(profile_tools)}")

    # Pre-flight: warn if the contract has obvious syntax errors
    _preflight_syntax_check(contract, quiet)

    all_results = []

    if RICH_AVAILABLE and not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task(
                f"Running {len(profile_tools)} tools in parallel...",
                total=len(profile_tools),
            )

            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=get_max_workers(default=len(profile_tools))) as pool:
                futures = {
                    pool.submit(run_tool, tool, contract, 300, llm_enhance=llm_enhance): tool
                    for tool in profile_tools
                }
                for future in as_completed(futures):
                    tool = futures[future]
                    try:
                        tool_result = future.result()
                        all_results.append(tool_result)
                    except Exception as e:
                        all_results.append(
                            {"tool": tool, "status": "error", "error": str(e), "findings": []}
                        )
                    progress.update(task, description=f"Done: {tool}")
                    progress.advance(task)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if not quiet:
            info(f"Running {len(profile_tools)} tools in parallel...")
        with ThreadPoolExecutor(max_workers=get_max_workers(default=len(profile_tools))) as pool:
            futures = {pool.submit(run_tool, tool, contract, 300): tool for tool in profile_tools}
            for future in as_completed(futures):
                try:
                    all_results.append(future.result())
                except Exception as e:
                    all_results.append(
                        {
                            "tool": futures[future],
                            "status": "error",
                            "error": str(e),
                            "findings": [],
                        }
                    )

    # Apply FP filter based on strictness (v5.1.2+)
    if fp_strictness.lower() != "off":
        try:
            from miesc.ml.fp_filter import FalsePositiveFilter

            with open(contract, encoding="utf-8") as contract_handle:
                code = contract_handle.read()
            fp_filter = FalsePositiveFilter(strictness=fp_strictness.lower(), use_rag=False)
            filtered_count = 0
            for result in all_results:
                kept = []
                for finding in result.get("findings", []):
                    fr = fp_filter.filter_finding(finding, code_context=code, file_path=contract)
                    if not fr.is_likely_fp:
                        kept.append(finding)
                    else:
                        filtered_count += 1
                result["findings"] = kept
            if not quiet and filtered_count > 0:
                info(
                    f"FP filter ({fp_strictness}): removed {filtered_count} likely false positives"
                )
        except Exception as e:
            if not quiet:
                info(f"FP filter skipped: {e}")

    # Ensemble mode: run multiple providers and merge findings
    if ensemble:
        frontier_model = None  # ensemble handles its own providers
        try:
            from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
            from miesc.core.tool_protocol import ToolStatus

            ensemble_providers = [
                ("anthropic", "claude-sonnet-4-6", "Claude"),
                ("openai", "gpt-4o", "GPT-4o"),
                ("ollama", "qwen2.5-coder:32b", "Ollama"),
            ]
            ensemble_findings = []
            seen_keys = set()

            for provider, model_id, label in ensemble_providers:
                adapter = FrontierLLMAdapter(provider=provider)
                if adapter.is_available() != ToolStatus.AVAILABLE:
                    if not quiet:
                        info(f"  Ensemble: {label} not available, skipping")
                    continue
                if not quiet:
                    info(f"  Ensemble: running {label} ({model_id})...")
                try:
                    result = adapter.analyze(str(contract), model=model_id)
                    if result.get("status") == "success":
                        for f in result.get("findings", []):
                            key = (
                                (f.get("type") or f.get("title") or "").lower()[:30],
                                (
                                    f.get("location", {}).get("function", "")
                                    if isinstance(f.get("location"), dict)
                                    else ""
                                ).lower(),
                            )
                            if key not in seen_keys:
                                seen_keys.add(key)
                                f["ensemble_source"] = label
                                ensemble_findings.append(f)
                        if not quiet:
                            info(
                                f"  Ensemble: {label} found {len(result.get('findings', []))} findings"
                            )
                except Exception as e:
                    if not quiet:
                        info(f"  Ensemble: {label} failed: {e}")

            if ensemble_findings:
                all_results.append(
                    {
                        "tool": "frontier-ensemble",
                        "status": "success",
                        "findings": ensemble_findings,
                    }
                )
                if not quiet:
                    info(
                        f"Ensemble: {len(ensemble_findings)} unique findings from {len(ensemble_providers)} providers"
                    )
        except Exception as e:
            if not quiet:
                info(f"Ensemble skipped: {e}")

    # Frontier LLM analysis (opt-in via --model claude/gpt)
    if frontier_model:
        try:
            from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter

            provider_map = {
                "claude": ("anthropic", "claude-sonnet-4-6"),
                "claude-opus": ("anthropic", "claude-opus-4-6"),
                "claude-sonnet": ("anthropic", "claude-sonnet-4-6"),
                "gpt": ("openai", "gpt-4o"),
                "gpt-4o": ("openai", "gpt-4o"),
                "gpt-4.1": ("openai", "gpt-4.1"),
                "gpt-5": ("openai", "gpt-5"),
                "deepseek-v4-pro": ("openai", "deepseek-v4-pro"),
                "deepseek-v4-flash": ("openai", "deepseek-v4-flash"),
                "ollama": ("ollama", "qwen2.5-coder:32b"),
                "qwen32b": ("ollama", "qwen2.5-coder:32b"),
                "qwen14b": ("ollama", "qwen2.5-coder:14b"),
                "codellama": ("ollama", "codellama:13b"),
            }
            provider, model_id = provider_map.get(frontier_model.lower(), ("auto", None))
            # DeepSeek V4 is OpenAI-compatible: point the OpenAI client at the
            # DeepSeek endpoint using DEEPSEEK_API_KEY.
            if frontier_model.lower().startswith("deepseek") and os.environ.get(
                "DEEPSEEK_API_KEY"
            ):
                os.environ["OPENAI_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
                os.environ["OPENAI_BASE_URL"] = os.environ.get(
                    "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
                )
            adapter = FrontierLLMAdapter(provider=provider)

            if (
                adapter.is_available()
                == __import__(
                    "miesc.core.tool_protocol", fromlist=["ToolStatus"]
                ).ToolStatus.AVAILABLE
            ):
                if not quiet:
                    info(f"Running frontier LLM analysis ({frontier_model})...")
                kwargs = {"model": model_id} if model_id else {}
                if deep:
                    kwargs["deep"] = True
                frontier_result = adapter.analyze(str(contract), **kwargs)
                if frontier_result.get("status") == "success":
                    frontier_findings = frontier_result.get("findings", [])
                    if not quiet:
                        info(f"Frontier LLM found {len(frontier_findings)} findings")
                    all_results.append(frontier_result)
                elif not quiet:
                    warning(f"Frontier LLM error: {frontier_result.get('error', 'unknown')}")
            elif not quiet:
                warning(
                    "Frontier LLM not available — check API key "
                    "(ANTHROPIC_API_KEY or OPENAI_API_KEY)"
                )
        except Exception as e:
            if not quiet:
                info(f"Frontier LLM skipped: {e}")

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
                code_text = Path(contract).read_text(encoding="utf-8")
            except Exception:
                code_text = ""
            enhanced = enhance_findings(
                all_findings_flat, source_code=code_text, file_path=str(contract)
            )
            non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
            suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
            # Preserve per-tool metadata (without findings) for report layer coverage,
            # then add the consolidated intelligence result with all enhanced findings.
            tool_metadata = [{k: v for k, v in r.items() if k != "findings"} for r in all_results]
            all_results = tool_metadata + [
                {"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}
            ]
            if not quiet and suppressed_count > 0:
                info(f"Intelligence engine: suppressed {suppressed_count} likely false positives")
            if not quiet and len(non_suppressed) < len(all_findings_flat):
                deduped = len(all_findings_flat) - len(enhanced)
                if deduped > 0:
                    info(f"Intelligence engine: merged {deduped} duplicate findings across tools")
    except Exception as e:
        if not quiet:
            info(f"Intelligence engine skipped: {e}")

    # LLM enhancement: call Ollama to add plain-English interpretation
    # to the top critical/high findings (opt-in via --llm-enhance)
    if llm_enhance:
        try:
            from miesc.reports.llm_interpreter import LLMReportInterpreter

            interp = LLMReportInterpreter()
            if interp.is_available():
                if not quiet:
                    info("Enhancing top findings with LLM insights (Ollama)...")
                try:
                    code_text = Path(contract).read_text(encoding="utf-8")
                except Exception:
                    code_text = ""
                critical_high = []
                for r in all_results:
                    for f in r.get("findings", []):
                        sev = (f.get("severity") or "").upper()
                        if sev in ("CRITICAL", "HIGH"):
                            critical_high.append(f)
                if critical_high:
                    interpretations = interp.interpret_critical_findings(
                        critical_high, contract_code=code_text
                    )
                    for interp_dict in interpretations:
                        title = interp_dict.get("title", "")
                        llm_text = interp_dict.get("llm_interpretation", "")
                        if not llm_text:
                            continue
                        for f in critical_high:
                            f_title = f.get("type") or f.get("title") or ""
                            if f_title.lower() == title.lower():
                                f["llm_interpretation"] = llm_text
                                break
                    enhanced_count = sum(1 for f in critical_high if f.get("llm_interpretation"))
                    if not quiet:
                        info(f"LLM insights added to {enhanced_count} critical/high findings")
            elif not quiet:
                warning("LLM enhance: Ollama not available at localhost:11434")
        except Exception as e:
            if not quiet:
                info(f"LLM enhance skipped: {e}")

    _display_and_save(
        all_results,
        contract=str(contract),
        output=output,
        quiet=quiet,
        verbose=verbose,
        ci=ci,
        verify_fp=verify_fp,
        verify_model=verify_model,
        rank=rank,
        baseline_path=baseline_path,
        fail_on_new=fail_on_new,
        annotate=annotate,
        notify_url=notify_url,
        slack_url=slack_url,
        notify_min_severity=notify_min_severity,
    )


def _preflight_syntax_check(contract: str, quiet: bool) -> None:
    """Warn the user if the Solidity file has syntax errors.

    Runs ``solc --stop-after parsing`` if solc is available. Never blocks
    the scan — this is advisory only.
    """
    import subprocess as _sp

    # Find solc: prefer solc-select artifact, then PATH
    from pathlib import Path as _Path

    solc = None
    # Try solc-select first
    global_ver = _Path.home() / ".solc-select" / "global-version"
    if global_ver.exists():
        ver = global_ver.read_text().strip()
        candidate = _Path.home() / ".solc-select" / "artifacts" / f"solc-{ver}" / f"solc-{ver}"
        if candidate.exists():
            solc = str(candidate)
    if not solc:
        import shutil

        solc = shutil.which("solc")
    if not solc:
        return

    try:
        result = _sp.run(
            [solc, "--stop-after", "parsing", contract],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 and not quiet:
            warning("Contract has syntax errors — analysis may be incomplete:")
            for line in result.stderr.strip().splitlines()[:5]:
                info(f"  {line}")
    except Exception:
        pass  # solc not usable — skip silently


# =============================================================================
# Private helpers
# =============================================================================


def _get_scan_profile(profile_name: str | None) -> dict[str, Any] | None:
    if not profile_name:
        return None
    profile = get_profile(profile_name)
    if not profile:
        raise click.ClickException(f"Profile '{profile_name}' not found")
    return profile


def _profile_uses_agentic_path(profile: dict[str, Any]) -> bool:
    return bool(profile.get("agentic_ensemble") or profile.get("enable_agentic_invariants"))


def _profile_tools(profile: dict[str, Any] | None) -> list[str]:
    if not profile:
        return list(QUICK_TOOLS)
    tools = profile.get("tools", QUICK_TOOLS)
    if isinstance(tools, list) and tools:
        return [str(tool) for tool in tools]
    return list(QUICK_TOOLS)


def _run_agentic_scan_profile(
    profile_name: str,
    profile: dict[str, Any],
    contract: str,
    *,
    output: str | None,
    quiet: bool,
    verbose: bool,
    ci: bool,
    verify_fp: bool,
    verify_model: str | None,
    rank: bool,
    baseline_path: str | None = None,
    fail_on_new: bool = False,
    annotate: str | None = None,
    notify_url: str | None = None,
    slack_url: str | None = None,
    notify_min_severity: str = "low",
) -> None:
    from miesc.cli.commands.audit import _apply_deep_profile_config
    from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

    if not quiet:
        print_banner()
        info(f"Scanning {contract}")
        info(f"Profile: {profile_name} | {profile.get('description', '')}")
        info("Route: agentic scan profile")

    config = DeepAuditConfig(
        timeout_seconds=int(profile.get("timeout", 600)),
        max_iterations=int(profile.get("max_iterations", 5)),
        enable_llm=bool(profile.get("enable_ai_triage", False)),
        enable_rag=not bool(profile.get("skip_rag", False)),
    )
    config, _profile = _apply_deep_profile_config(config, profile_name)
    result = DeepAuditAgent(config=config).analyze(contract)
    all_results = [
        {
            "tool": "miesc-agentic-scan-profile",
            "status": "success",
            "contract": contract,
            "findings": result.get("findings", []),
            "metadata": result.get("metadata", {}),
        }
    ]
    _display_and_save(
        all_results,
        contract=contract,
        output=output,
        quiet=quiet,
        verbose=verbose,
        ci=ci,
        verify_fp=verify_fp,
        verify_model=verify_model,
        rank=rank,
        baseline_path=baseline_path,
        fail_on_new=fail_on_new,
        annotate=annotate,
        notify_url=notify_url,
        slack_url=slack_url,
        notify_min_severity=notify_min_severity,
    )


def _scan_single_file(
    contract: str,
    all_results: list[dict[str, Any]],
    *,
    quiet: bool,
    llm_enhance: bool,
    tools: list[str] | None = None,
) -> None:
    """Run QUICK_TOOLS against a single .sol file and append results to all_results.

    Each result dict is tagged with the originating contract path so that
    directory-mode callers can trace findings back to their source file.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    scan_tools = tools or list(QUICK_TOOLS)
    with ThreadPoolExecutor(max_workers=get_max_workers(default=len(scan_tools))) as pool:
        futures = {
            pool.submit(run_tool, tool, contract, 300, llm_enhance=llm_enhance): tool
            for tool in scan_tools
        }
        for future in as_completed(futures):
            tool = futures[future]
            try:
                result: dict[str, Any] = future.result()
            except Exception as e:
                result = {"tool": tool, "status": "error", "error": str(e), "findings": []}
            result["contract"] = contract
            all_results.append(result)


def _apply_verify_fp(
    all_results: list[dict[str, Any]], *, contract: str, model: str | None, quiet: bool
) -> None:
    """Recall-safe benign-context verifier as a post-scan FP filter (mutates findings).

    Drops only findings the contract clearly mitigates (reentrancy guard, onlyOwner,
    Sol>=0.8, SafeERC20, ...); weakly-grounded findings are flagged needs_review and
    KEPT. Rule-only by default; opt-in LLM grounding via `model` (Ollama, with DeepSeek
    API failover). Never drops a real finding on a weak signal.
    """
    try:
        from miesc.ml.benign_context_verifier import apply_to_results
    except Exception as e:  # noqa: BLE001
        if not quiet:
            info(f"verify-fp skipped: {e}")
        return
    dropped_total, flagged_total = apply_to_results(all_results, contract=contract, model=model)
    if not quiet:
        mode = f"LLM {model}" if model else "rule-only"
        info(
            f"verify-fp ({mode}): dropped {dropped_total} benign-context FP(s), "
            f"flagged {flagged_total} for review — real findings kept (recall-safe)"
        )


def _apply_triage_rank(all_results: list[dict[str, Any]], *, contract: str, quiet: bool) -> None:
    """Recall-safe triage: reorder each result's findings by P(real) (most-likely-real first).
    Never drops a finding (recall 1.0). No-ops gracefully if no trained model is present."""
    try:
        from miesc.ml.triage_ranker import rank_results
    except Exception as e:  # noqa: BLE001
        if not quiet:
            info(f"rank skipped: {e}")
        return
    total = rank_results(all_results, contract=contract)
    if not quiet:
        if total < 0:
            info("rank: no triage model — train with scripts/train_triage_model.py "
                 "(order unchanged)")
        else:
            info(f"rank: ordered {total} finding(s) by P(real) — triage, recall-safe (nothing dropped)")


def _display_and_save(
    all_results: list[dict[str, Any]],
    *,
    contract: str,
    output: str | None,
    quiet: bool,
    verbose: bool,
    ci: bool,
    verify_fp: bool = False,
    verify_model: str | None = None,
    rank: bool = False,
    baseline_path: str | None = None,
    fail_on_new: bool = False,
    annotate: str | None = None,
    notify_url: str | None = None,
    slack_url: str | None = None,
    notify_min_severity: str = "low",
) -> None:
    """Display the scan summary table, optionally save JSON, and handle CI exit."""
    if verify_fp:
        _apply_verify_fp(all_results, contract=contract, model=verify_model, quiet=quiet)
    if rank:
        _apply_triage_rank(all_results, contract=contract, quiet=quiet)
    # Detect tool failures — help users who installed miesc without slither/aderyn
    tools_succeeded = [r for r in all_results if r.get("status") != "error"]
    tools_errored = [r for r in all_results if r.get("status") == "error"]

    if tools_errored and not tools_succeeded and not quiet:
        error("All analysis tools failed. Check tool availability:")
        for r in tools_errored:
            info(f"  {r.get('tool', '?')}: {r.get('error', 'unknown error')}")
        info("")
        info("Run 'miesc doctor' to check which tools are installed.")
        info("Quick fix: pip install slither-analyzer  (most common)")

    summary = summarize_findings(all_results)
    total = sum(summary.values())
    critical_high = summary.get("CRITICAL", 0) + summary.get("HIGH", 0)

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title="Scan Results", box=box.ROUNDED)
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
            if count > 0:  # Only show non-zero
                table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)

        if critical_high > 0:
            console.print(
                f"\n[bold red]Found {critical_high} critical/high severity issues![/bold red]"
            )
        elif total > 0:
            console.print(f"\n[yellow]Found {total} issues to review[/yellow]")
        elif tools_errored:
            console.print(
                f"\n[dim]0 findings — but {len(tools_errored)}/{len(all_results)} "
                f"tools errored. Run 'miesc doctor' to diagnose.[/dim]"
            )
        else:
            console.print("\n[green]No issues found![/green]")
    else:
        print("\n=== Scan Results ===")  # noqa: T201
        for sev, count in summary.items():
            if count > 0:
                print(f"{sev}: {count}")  # noqa: T201
        print(f"TOTAL: {total}")  # noqa: T201

    # Verbose mode: show per-finding details with confidence + remediation
    if verbose and not quiet:
        all_findings_verbose = []
        for r in all_results:
            all_findings_verbose.extend(r.get("findings", []))

        if all_findings_verbose:
            console.print("\n[bold]Detailed Findings[/bold]\n")
            for i, f in enumerate(all_findings_verbose, 1):
                sev = f.get("severity", "?")
                ftype = f.get("type", f.get("title", "?"))
                conf = f.get("confidence", "")
                tools = f.get("confirming_tools", [f.get("tool", "?")])
                rec = f.get("recommendation", f.get("message", ""))
                canonical = f.get("canonical_category", "")

                sev_color = {
                    "Critical": "red",
                    "High": "red",
                    "Medium": "yellow",
                    "Low": "cyan",
                }.get(sev, "white")
                conf_str = f" conf={conf:.0%}" if isinstance(conf, float) else ""
                tools_str = ", ".join(tools) if isinstance(tools, list) else str(tools)

                console.print(
                    f"  [bold]{i}.[/bold] [{sev_color}]{sev}[/{sev_color}] "
                    f"[bold]{ftype}[/bold]{conf_str}"
                )
                if canonical:
                    console.print(f"     Category: {canonical} | Tools: {tools_str}")
                if rec and len(rec) > 5:
                    console.print(f"     [dim]Fix: {rec[:200]}[/dim]")
                console.print()

    # Save output
    if output:
        # Consolidate all findings into a single list
        all_findings: list[dict[str, Any]] = []
        for r in all_results:
            for f in r.get("findings", []):
                f.setdefault("tool", r.get("tool", "unknown"))
                all_findings.append(f)

        tools_used = sorted(
            {r.get("tool", "") for r in all_results if r.get("status") != "error" and r.get("tool")}
        )
        tools_failed = sorted(
            {r.get("tool", "") for r in all_results if r.get("status") == "error" and r.get("tool")}
        )

        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "success": True,
            "summary": summary,
            "total_findings": total,
            "tools": tools_used,
            "tools_failed": tools_failed,
            "findings": all_findings,
            "results": all_results,
        }
        with open(output, "w", encoding="utf-8") as output_handle:
            json.dump(data, output_handle, indent=2, default=str)
        success(f"Report saved to {output}")

    # Inline CI annotations (e.g. GitHub Actions ::error/::warning workflow
    # commands). Emitted BEFORE the baseline/CI exit so annotations render even
    # when the run is about to fail. With --baseline, only new findings annotate.
    if annotate == "github":
        from miesc.core.baseline import diff_against_baseline, load_baseline
        from miesc.core.exporters import GitHubAnnotationsExporter

        annotate_findings: list[dict[str, Any]] = []
        for r in all_results:
            for f in r.get("findings", []):
                f.setdefault("file", r.get("contract", contract))
                annotate_findings.append(f)

        if baseline_path:
            try:
                baseline_obj = load_baseline(baseline_path)
                annotate_findings = diff_against_baseline(annotate_findings, baseline_obj)["new"]
            except (FileNotFoundError, ValueError) as exc:
                if not quiet:
                    warning(f"annotate: baseline unusable, annotating all findings: {exc}")

        for line in GitHubAnnotationsExporter().to_github_annotations(annotate_findings):
            click.echo(line)

    # Baseline suppression gate: report new/known/fixed and optionally fail on new
    if baseline_path:
        from miesc.cli.commands.baseline import apply_baseline_gate

        gate_findings: list[dict[str, Any]] = []
        for r in all_results:
            for f in r.get("findings", []):
                gate_findings.append(f)
        apply_baseline_gate(
            gate_findings, baseline_path, fail_on_new=fail_on_new, quiet=quiet
        )

    # Outbound notifications (webhook / Slack). Fire BEFORE the CI exit so a
    # channel is alerted even when the run is about to fail. SSRF-guarded and
    # error-swallowing: a broken sink never aborts the scan.
    if notify_url or slack_url:
        from miesc.core.notifiers import dispatch_notifications

        delivered = dispatch_notifications(
            all_results,
            str(contract),
            webhook_url=notify_url,
            slack_url=slack_url,
            min_severity=notify_min_severity,
            ci_failed=critical_high > 0,
        )
        if not quiet:
            for sink, ok in delivered.items():
                info(f"notify[{sink}]: {'sent' if ok else 'skipped/failed'}")

    # CI mode exit
    if ci and critical_high > 0:
        error(f"CI check failed: {critical_high} critical/high issues")
        sys.exit(1)

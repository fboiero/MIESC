"""Subscription-authenticated transports for Claude Code and Codex CLIs."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def check_claude_cli() -> bool:
    """Return whether the Claude Code CLI is on PATH."""
    return shutil.which("claude") is not None


def check_codex_cli() -> bool:
    """Return whether the Codex CLI is on PATH."""
    return shutil.which("codex") is not None


def classify_cli_error(output: str, cli_name: str) -> str:
    """Turn CLI output into a short actionable error."""
    lines = output.strip().splitlines()

    def matching_line(*signals: str) -> str:
        for line in lines:
            if any(signal in line.lower() for signal in signals):
                return line.strip()[:300]
        return output.strip()[:300]

    normalized = output.lower()
    if "usage limit" in normalized or "usage_limit" in normalized:
        return (
            f"{cli_name} subscription usage limit reached. "
            f"{matching_line('usage limit', 'usage_limit')}"
        )
    if "rate limit" in normalized or "rate_limit" in normalized or " 429" in normalized:
        return (
            f"{cli_name} rate limited the request. "
            f"{matching_line('rate limit', 'rate_limit', ' 429')}"
        )
    if any(signal in normalized for signal in ("not logged in", "unauthorized", "authentication")):
        return f"{cli_name} is not authenticated. Run its login command first."
    return f"{cli_name} CLI failed: {output.strip()[:300]}"


def call_claude_cli(
    prompt: str,
    *,
    system_prompt: str = "",
    model: str = "sonnet",
    timeout: int = 180,
    tools: str = "",
    cwd: str | None = None,
) -> str:
    """Run Claude Code with the user's existing subscription login.

    ``tools`` defaults to "" (no tool access — a one-shot text-in/text-out
    call, the shape used by finding_validator/frontier_llm_adapter). Pass a
    comma-separated allowlist (e.g. "Read,Grep,Glob") + ``cwd`` to let the CLI
    read the given directory itself instead of stuffing source into the
    prompt — see ``call_claude_cli_agentic``.
    """
    cmd = [
        "claude",
        "-p",
        "--model",
        model,
        "--output-format",
        "json",
        "--no-session-persistence",
        "--tools",
        tools,
        "--permission-mode",
        "dontAsk",
        "--strict-mcp-config",
        "--setting-sources",
        "",
    ]
    if system_prompt:
        cmd.extend(["--append-system-prompt", system_prompt])

    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "claude CLI not found on PATH. Install: https://claude.com/claude-code"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Claude Code CLI timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise RuntimeError(classify_cli_error(proc.stdout + proc.stderr, "Claude Code"))

    try:
        wrapper = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Claude Code CLI returned non-JSON output: {proc.stdout[:200]}"
        ) from exc

    if wrapper.get("is_error"):
        raise RuntimeError(classify_cli_error(str(wrapper.get("result", "")), "Claude Code"))
    return str(wrapper.get("result", ""))


def call_claude_cli_agentic(
    prompt: str,
    *,
    cwd: str,
    system_prompt: str = "",
    model: str = "sonnet",
    timeout: int = 1200,
    tools: str = "Read,Grep,Glob",
) -> str:
    """Run Claude Code as a read-only, tool-using agent over a repo directory.

    Unlike ``call_claude_cli`` (no tools, source pasted into the prompt), this
    lets the CLI read the directory itself — ``cwd`` is where it runs, so
    ``Read``/``Grep``/``Glob`` see the real repo. Read-only by design: no
    ``Bash``/``Write``, no code execution. ``timeout`` defaults to 20 minutes,
    the measured ceiling for a whole small protocol (see MEJORAS4.md item #1).
    """
    return call_claude_cli(
        prompt,
        system_prompt=system_prompt,
        model=model,
        timeout=timeout,
        tools=tools,
        cwd=cwd,
    )


def call_codex_cli(prompt: str, *, model: str | None = None, timeout: int = 180) -> str:
    """Run Codex with the user's existing ChatGPT subscription login."""
    with tempfile.TemporaryDirectory(prefix="miesc-codex-") as sandbox_dir:
        output_path = Path(sandbox_dir) / "codex_result.txt"
        cmd = [
            "codex",
            "exec",
            "-",
            "-C",
            sandbox_dir,
            "-s",
            "read-only",
            "--ephemeral",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "-o",
            os.fspath(output_path),
        ]
        if model:
            cmd.extend(["-m", model])

        try:
            proc = subprocess.run(
                cmd, input=prompt, capture_output=True, text=True, timeout=timeout
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "codex CLI not found on PATH. Install: https://github.com/openai/codex"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Codex CLI timed out after {timeout}s") from exc

        if proc.returncode != 0 or not output_path.exists():
            raise RuntimeError(classify_cli_error(proc.stdout + proc.stderr, "Codex"))
        return output_path.read_text(encoding="utf-8")

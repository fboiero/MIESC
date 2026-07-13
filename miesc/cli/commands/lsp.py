"""
MIESC CLI - LSP Command

Starts the MIESC Language Server over stdio so any LSP-capable editor
(VS Code, JetBrains, Neovim, ...) gets inline security diagnostics and
deterministic quick-fixes from one MIESC core.

The server speaks JSON-RPC framed with Content-Length headers on stdin/stdout.
It is meant to be launched by an editor extension, not run interactively.

Author: Fernando Boiero
License: AGPL-3.0
"""

import click


@click.command()
@click.option(
    "--debounce",
    "-d",
    type=float,
    default=1.0,
    help="Debounce window (seconds) for save/change re-scans (default: 1.0).",
)
def lsp(debounce: float) -> None:
    """Start the MIESC Language Server (LSP over stdio).

    Reads LSP JSON-RPC messages on stdin and writes responses/notifications on
    stdout. An editor extension launches this command and connects to it.

    Features (minimal-viable):
      textDocument/didOpen, didSave  → inline security diagnostics
      textDocument/codeAction        → deterministic quick-fixes

    \b
    Example (editor launch config):
      command: miesc lsp
      transport: stdio
    """
    from miesc.lsp.server import LspServer

    server = LspServer(debounce=debounce)
    server.serve()

"""
MIESC API Module - Django REST Framework API

Provides REST endpoints for smart contract security analysis:
- POST /api/v1/analyze/quick/ - Quick 4-tool scan
- POST /api/v1/analyze/full/ - Complete 7-layer audit
- POST /api/v1/analyze/layer/{n}/ - Run specific layer
- POST /api/v1/analyze/tool/{name}/ - Run single tool
- GET /api/v1/tools/ - List available tools
- GET /api/v1/tools/{name}/ - Tool information
- GET /api/v1/layers/ - Layer information
- GET /api/v1/health/ - System health check
- GET /api/v1/reports/ - Manage audit reports

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

from miesc import __version__  # Use centralized version

# Export main components - these are intentional re-exports for the public API
try:
    from miesc.api.rest import (  # noqa: F401
        ADAPTER_MAP,
        LAYERS,
        QUICK_TOOLS,
        VERSION,
        AdapterLoader,
        app,
        create_app,
        get_wsgi_application,
        run_full_audit,
        run_layer,
        run_server,
        run_tool,
        summarize_findings,
        to_sarif,
    )

    __all__ = [
        "app",
        "get_wsgi_application",
        "create_app",
        "run_server",
        "AdapterLoader",
        "run_tool",
        "run_layer",
        "run_full_audit",
        "summarize_findings",
        "to_sarif",
        "LAYERS",
        "ADAPTER_MAP",
        "QUICK_TOOLS",
        "VERSION",
    ]
except ImportError as e:
    # Allow package to be imported even if dependencies missing
    import logging

    logging.getLogger(__name__).warning(f"Could not import REST API components: {e}")
    __all__ = []

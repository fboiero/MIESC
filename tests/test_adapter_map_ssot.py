"""SSOT guards for the adapter inventory.

The REST API (``miesc.api.rest``) and the HealthChecker
(``miesc.core.health_checker``) used to each carry their own hand-maintained
copy of the adapter map, which drifted from the canonical inventory in
``miesc.cli.constants`` (REST stuck at 50 tools, HealthChecker at 23, versus the
canonical 56). These tests lock those surfaces to the single source of truth so
a stale local copy can never be reintroduced.
"""

import importlib

from miesc.cli.constants import ADAPTER_MAP as CANONICAL


def test_rest_adapter_map_is_the_canonical_one():
    from miesc.api.rest import ADAPTER_MAP as rest_map

    assert rest_map == CANONICAL


def test_rest_layers_are_the_canonical_ones():
    from miesc.api.rest import LAYERS as rest_layers
    from miesc.cli.constants import LAYERS as canonical_layers

    assert rest_layers == canonical_layers


def test_health_checker_map_covers_the_canonical_inventory():
    from miesc.core.health_checker import HealthChecker

    # Same tools as the canonical inventory, derived (never a hand-kept copy)...
    assert set(HealthChecker.ADAPTER_MAP) == set(CANONICAL)
    # ...each carrying (module_path, class_name) with the canonical class name
    # and the ``{tool}_adapter`` module convention the CLI loader uses.
    for tool, (module_path, class_name) in HealthChecker.ADAPTER_MAP.items():
        assert class_name == CANONICAL[tool]
        assert module_path == f"miesc.adapters.{tool}_adapter"


def test_health_checker_map_tuples_all_import():
    from miesc.core.health_checker import HealthChecker

    for _tool, (module_path, class_name) in HealthChecker.ADAPTER_MAP.items():
        module = importlib.import_module(module_path)
        assert getattr(module, class_name, None) is not None, f"{module_path}.{class_name}"

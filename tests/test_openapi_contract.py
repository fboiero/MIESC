import re
from pathlib import Path

import yaml

REST_SOURCE = Path("miesc/api/rest.py")
OPENAPI_SPEC = Path("docs/openapi.yaml")


def _route_to_openapi(route: str) -> str:
    route = "/" + route.lstrip("/")
    route = route.replace("<int:", "{").replace("<str:", "{")
    route = route.replace(">", "}")
    return route


def _implemented_openapi_routes() -> dict[str, set[str]]:
    rest_source = REST_SOURCE.read_text()
    view_methods = {
        match.group("view"): {
            method.lower() for method in re.findall(r'"([A-Z]+)"', match.group("methods"))
        }
        for match in re.finditer(
            r"@api_view\(\[(?P<methods>[^\]]+)\]\)\s*"
            r"(?:@permission_classes\(\[AllowAny\]\)\s*)?"
            r"def (?P<view>\w+)\(",
            rest_source,
        )
    }
    routes = {}
    for match in re.finditer(
        r'path\(\s*"(?P<route>[^"]*)"\s*,\s*(?P<view>\w+)',
        rest_source,
    ):
        methods = view_methods.get(match.group("view"), set())
        routes[_route_to_openapi(match.group("route"))] = methods
    return routes


def test_openapi_public_paths_are_implemented():
    implemented_paths = set(_implemented_openapi_routes())
    spec = yaml.safe_load(OPENAPI_SPEC.read_text())

    assert set(spec["paths"]) <= implemented_paths


def test_openapi_public_methods_are_implemented():
    implemented_routes = _implemented_openapi_routes()
    spec = yaml.safe_load(OPENAPI_SPEC.read_text())

    for path, operations in spec["paths"].items():
        documented_methods = set(operations)
        assert documented_methods <= implemented_routes[path]

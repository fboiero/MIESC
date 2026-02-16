"""
Plugin Marketplace - Remote Plugin Index Client
================================================

Fetches and manages the remote MIESC plugin marketplace index
hosted on GitHub. Provides search, browse, and compatibility
checking for community plugins.

The marketplace is a curated JSON index. Plugins are distributed
via PyPI. Submissions happen via Pull Requests.

Usage:
    from src.plugins.marketplace import MarketplaceClient

    client = MarketplaceClient()
    results = client.search("flash loan")
    for r in results:
        print(f"{r.plugin.name} ({r.plugin.version})")

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: February 2026
Version: 1.0.0
"""

import ipaddress
import json
import logging
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Security: Whitelist of allowed hosts for marketplace index
ALLOWED_MARKETPLACE_HOSTS = {
    "raw.githubusercontent.com",
    "api.github.com",
    "github.com",
}


def _validate_marketplace_url(url: str) -> str:
    """
    Validate marketplace URL to prevent SSRF attacks.

    Security controls:
    - Only HTTPS allowed (except localhost for development)
    - Block private/reserved IP addresses
    - Whitelist of allowed hosts

    Args:
        url: URL to validate

    Returns:
        Validated URL

    Raises:
        MarketplaceError: If URL fails security validation
    """
    parsed = urlparse(url)

    # Check scheme - only HTTPS allowed (or http://localhost for dev)
    if parsed.scheme == "http":
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise MarketplaceError(
                f"Only HTTPS URLs allowed for marketplace. Got: {parsed.scheme}://"
            )
    elif parsed.scheme != "https":
        raise MarketplaceError(
            f"Invalid URL scheme for marketplace: {parsed.scheme}. Use HTTPS."
        )

    hostname = parsed.hostname
    if not hostname:
        raise MarketplaceError("Invalid URL: no hostname")

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        # Block private, loopback, reserved IPs (except localhost for dev)
        if ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_link_local:
            if str(ip) not in ("127.0.0.1", "::1"):
                raise MarketplaceError(
                    f"Access to private/reserved IP addresses blocked: {ip}"
                )
    except ValueError:
        # Not an IP address, it's a hostname - check against whitelist
        if hostname not in ALLOWED_MARKETPLACE_HOSTS:
            # Also block cloud metadata endpoints
            if hostname in ("169.254.169.254", "metadata.google.internal"):
                raise MarketplaceError(
                    f"Access to cloud metadata endpoints blocked: {hostname}"
                )

            # Resolve hostname and check resulting IP
            try:
                resolved_ips = socket.getaddrinfo(hostname, None)
                for family, _, _, _, sockaddr in resolved_ips:
                    ip_str = sockaddr[0]
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if ip.is_private or ip.is_reserved or ip.is_loopback:
                            raise MarketplaceError(
                                f"Hostname {hostname} resolves to private IP {ip}"
                            )
                    except ValueError:
                        continue
            except socket.gaierror:
                # DNS resolution failed - let the actual request handle this
                pass

            logger.warning(
                "Marketplace URL host '%s' not in whitelist. "
                "Allowed hosts: %s",
                hostname,
                ", ".join(sorted(ALLOWED_MARKETPLACE_HOSTS)),
            )

    return url


# Default marketplace configuration
DEFAULT_INDEX_URL = (
    "https://raw.githubusercontent.com/fboiero/MIESC/"
    "main/data/marketplace/marketplace-index.json"
)
DEFAULT_CACHE_PATH = Path.home() / ".miesc" / "marketplace_cache.json"
DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hour
REQUEST_TIMEOUT_SECONDS = 15

# Valid plugin types (lowercase, matching PluginType enum values)
VALID_PLUGIN_TYPES = {
    "detector",
    "adapter",
    "reporter",
    "transformer",
    "analyzer",
    "hook",
}


class VerificationStatus(Enum):
    """Plugin verification status in the marketplace."""

    VERIFIED = "verified"
    COMMUNITY = "community"
    EXPERIMENTAL = "experimental"


class MarketplaceError(Exception):
    """Base exception for marketplace errors."""


class MarketplaceUnavailableError(MarketplaceError):
    """Raised when the marketplace index cannot be fetched."""


@dataclass
class MarketplacePlugin:
    """A plugin entry from the marketplace index."""

    name: str
    slug: str
    pypi_package: str
    version: str
    plugin_type: str
    description: str
    author: str
    author_email: str = ""
    homepage: str = ""
    repository: str = ""
    license: str = ""
    tags: List[str] = field(default_factory=list)
    min_miesc_version: str = "4.0.0"
    max_miesc_version: Optional[str] = None
    verification_status: VerificationStatus = VerificationStatus.COMMUNITY
    added_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MarketplacePlugin":
        """Create from dictionary."""
        status_str = data.get("verification_status", "community")
        try:
            status = VerificationStatus(status_str)
        except ValueError:
            status = VerificationStatus.COMMUNITY

        return cls(
            name=data.get("name", ""),
            slug=data.get("slug", ""),
            pypi_package=data.get("pypi_package", ""),
            version=data.get("version", ""),
            plugin_type=data.get("plugin_type", ""),
            description=data.get("description", ""),
            author=data.get("author", ""),
            author_email=data.get("author_email", ""),
            homepage=data.get("homepage", ""),
            repository=data.get("repository", ""),
            license=data.get("license", ""),
            tags=data.get("tags", []),
            min_miesc_version=data.get("min_miesc_version", "4.0.0"),
            max_miesc_version=data.get("max_miesc_version"),
            verification_status=status,
            added_at=data.get("added_at", ""),
            updated_at=data.get("updated_at", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "name": self.name,
            "slug": self.slug,
            "pypi_package": self.pypi_package,
            "version": self.version,
            "plugin_type": self.plugin_type,
            "description": self.description,
            "author": self.author,
            "verification_status": self.verification_status.value,
            "tags": self.tags,
            "min_miesc_version": self.min_miesc_version,
        }
        # Only include non-empty optional fields
        if self.author_email:
            result["author_email"] = self.author_email
        if self.homepage:
            result["homepage"] = self.homepage
        if self.repository:
            result["repository"] = self.repository
        if self.license:
            result["license"] = self.license
        if self.max_miesc_version:
            result["max_miesc_version"] = self.max_miesc_version
        if self.added_at:
            result["added_at"] = self.added_at
        if self.updated_at:
            result["updated_at"] = self.updated_at
        return result

    def is_compatible(self, miesc_version: str) -> bool:
        """Check compatibility with a MIESC version."""
        return _version_in_range(miesc_version, self.min_miesc_version, self.max_miesc_version)


@dataclass
class MarketplaceIndex:
    """The full marketplace index."""

    version: str = "1.0"
    updated_at: str = ""
    plugins: List[MarketplacePlugin] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MarketplaceIndex":
        """Parse index from dictionary."""
        plugins = [MarketplacePlugin.from_dict(p) for p in data.get("plugins", [])]
        return cls(
            version=data.get("version", "1.0"),
            updated_at=data.get("updated_at", ""),
            plugins=plugins,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for caching."""
        return {
            "version": self.version,
            "updated_at": self.updated_at,
            "plugins": [p.to_dict() for p in self.plugins],
        }


@dataclass
class MarketplaceSearchResult:
    """Result from a marketplace search."""

    plugin: MarketplacePlugin
    relevance_score: float = 0.0
    is_installed: bool = False
    is_compatible: bool = True


class MarketplaceClient:
    """
    Client for the MIESC plugin marketplace.

    Fetches the remote plugin index from GitHub, caches it locally,
    and provides search/browse/compatibility functionality.
    """

    def __init__(
        self,
        index_url: str = DEFAULT_INDEX_URL,
        cache_path: Optional[Path] = None,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        miesc_version: Optional[str] = None,
    ):
        # Security: Validate URL to prevent SSRF attacks
        self.index_url = _validate_marketplace_url(index_url)
        self.cache_path = cache_path or DEFAULT_CACHE_PATH
        self.cache_ttl_seconds = cache_ttl_seconds
        self.miesc_version = miesc_version or _get_miesc_version()
        self._index: Optional[MarketplaceIndex] = None

    def fetch_index(self, force_refresh: bool = False) -> MarketplaceIndex:
        """
        Fetch the marketplace index.

        Uses cache if available and not expired.
        Falls back to cache on network errors (offline mode).
        """
        if not force_refresh and self._index is not None:
            return self._index

        if not force_refresh and self._is_cache_valid():
            cached = self._load_cache()
            if cached is not None:
                self._index = cached
                return cached

        try:
            index = self._fetch_remote_index()
            self._save_cache(index)
            self._index = index
            return index
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            OSError,
            MarketplaceError,
        ) as e:
            logger.warning("Failed to fetch remote index: %s", e)
            cached = self._load_cache()
            if cached is not None:
                logger.warning("Using cached marketplace index (may be outdated)")
                self._index = cached
                return cached
            raise MarketplaceUnavailableError(
                "Cannot fetch marketplace index and no cache available"
            ) from e

    def _fetch_remote_index(self) -> MarketplaceIndex:
        """Fetch index from the remote GitHub URL."""
        req = urllib.request.Request(
            self.index_url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"MIESC/{self.miesc_version}",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise MarketplaceError(f"Unexpected status {response.status} from marketplace")
            data = json.loads(response.read().decode("utf-8"))
            return MarketplaceIndex.from_dict(data)

    def _load_cache(self) -> Optional[MarketplaceIndex]:
        """Load index from local cache file."""
        try:
            if not self.cache_path.exists():
                return None
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return MarketplaceIndex.from_dict(data.get("index", {}))
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning("Failed to load marketplace cache: %s", e)
            return None

    def _save_cache(self, index: MarketplaceIndex) -> None:
        """Save index to local cache file."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_data = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": self.cache_ttl_seconds,
                "index": index.to_dict(),
            }
            self.cache_path.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to save marketplace cache: %s", e)

    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is within TTL."""
        try:
            if not self.cache_path.exists():
                return False
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            cached_at_str = data.get("cached_at", "")
            if not cached_at_str:
                return False
            cached_at = datetime.fromisoformat(cached_at_str)
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - cached_at).total_seconds()
            return age_seconds < self.cache_ttl_seconds
        except (json.JSONDecodeError, ValueError, OSError):
            return False

    def search(
        self,
        query: str,
        plugin_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        compatible_only: bool = True,
        verification_status: Optional[VerificationStatus] = None,
    ) -> List[MarketplaceSearchResult]:
        """
        Search the marketplace index.

        Searches name, description, tags, and author.
        Returns results sorted by relevance.
        """
        index = self.fetch_index()
        results = []
        query_lower = query.lower().strip()
        query_words = query_lower.split()

        for plugin in index.plugins:
            # Apply filters
            if plugin_type and plugin.plugin_type != plugin_type:
                continue
            if verification_status and plugin.verification_status != verification_status:
                continue
            if tags and not any(t in plugin.tags for t in tags):
                continue

            is_compat = plugin.is_compatible(self.miesc_version)
            if compatible_only and not is_compat:
                continue

            # Compute relevance score
            score = _compute_relevance(plugin, query_lower, query_words)
            if score <= 0:
                continue

            results.append(
                MarketplaceSearchResult(
                    plugin=plugin,
                    relevance_score=score,
                    is_installed=False,
                    is_compatible=is_compat,
                )
            )

        results.sort(key=lambda r: r.relevance_score, reverse=True)
        return results

    def browse(
        self,
        plugin_type: Optional[str] = None,
        verification_status: Optional[VerificationStatus] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> List[MarketplacePlugin]:
        """Browse plugins with optional filtering and pagination."""
        index = self.fetch_index()
        plugins = index.plugins

        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]
        if verification_status:
            plugins = [p for p in plugins if p.verification_status == verification_status]

        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        return plugins[start:end]

    def get_plugin(self, slug: str) -> Optional[MarketplacePlugin]:
        """Get a specific plugin by slug."""
        index = self.fetch_index()
        for plugin in index.plugins:
            if plugin.slug == slug:
                return plugin
        return None

    def get_plugin_by_package(self, pypi_package: str) -> Optional[MarketplacePlugin]:
        """Get a plugin by its PyPI package name."""
        index = self.fetch_index()
        for plugin in index.plugins:
            if plugin.pypi_package == pypi_package:
                return plugin
        return None

    def check_compatibility(self, plugin: MarketplacePlugin) -> Dict[str, Any]:
        """Check if a marketplace plugin is compatible."""
        compatible = plugin.is_compatible(self.miesc_version)
        if compatible:
            message = f"Compatible with MIESC {self.miesc_version}"
        else:
            message = (
                f"Requires MIESC {plugin.min_miesc_version}"
                + (f" - {plugin.max_miesc_version}" if plugin.max_miesc_version else "+")
                + f", current: {self.miesc_version}"
            )
        return {
            "compatible": compatible,
            "message": message,
            "miesc_version": self.miesc_version,
            "min_version": plugin.min_miesc_version,
            "max_version": plugin.max_miesc_version,
        }

    def get_install_command(self, plugin: MarketplacePlugin) -> str:
        """Get the pip install command for a plugin."""
        return f"pip install {plugin.pypi_package}"

    def generate_submission(
        self,
        name: str,
        pypi_package: str,
        version: str,
        plugin_type: str,
        description: str,
        author: str,
        author_email: str = "",
        homepage: str = "",
        repository: str = "",
        license_type: str = "MIT",
        tags: Optional[List[str]] = None,
        min_miesc_version: str = "5.0.0",
    ) -> Dict[str, Any]:
        """Generate a marketplace submission JSON entry."""
        slug = _slugify(name)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry: Dict[str, Any] = {
            "name": name,
            "slug": slug,
            "pypi_package": pypi_package,
            "version": version,
            "plugin_type": plugin_type,
            "description": description,
            "author": author,
            "verification_status": "community",
            "tags": tags or [],
            "min_miesc_version": min_miesc_version,
            "added_at": now,
            "updated_at": now,
        }
        if author_email:
            entry["author_email"] = author_email
        if homepage:
            entry["homepage"] = homepage
        if repository:
            entry["repository"] = repository
        if license_type:
            entry["license"] = license_type
        return entry

    def validate_submission(self, entry: Dict[str, Any]) -> List[str]:
        """
        Validate a submission entry.

        Returns list of validation error messages (empty = valid).
        """
        errors = []

        # Required fields
        required = [
            "name",
            "slug",
            "pypi_package",
            "version",
            "plugin_type",
            "description",
            "author",
        ]
        for field_name in required:
            if not entry.get(field_name):
                errors.append(f"Missing required field: {field_name}")

        # Slug format
        slug = entry.get("slug", "")
        if slug and not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", slug):
            errors.append("Invalid slug format: must be lowercase alphanumeric with hyphens")

        # Plugin type
        ptype = entry.get("plugin_type", "")
        if ptype and ptype not in VALID_PLUGIN_TYPES:
            errors.append(
                f"Invalid plugin_type: {ptype}. "
                f"Must be one of: {', '.join(sorted(VALID_PLUGIN_TYPES))}"
            )

        # Version format
        version = entry.get("version", "")
        if version and not re.match(r"^\d+\.\d+\.\d+", version):
            errors.append("Invalid version format: must be semver (e.g., 1.0.0)")

        # PyPI package naming
        package = entry.get("pypi_package", "")
        if package and not package.startswith("miesc-"):
            errors.append("PyPI package name should start with 'miesc-'")

        # Check slug uniqueness against current index
        if slug and self._index is not None:
            for p in self._index.plugins:
                if p.slug == slug:
                    errors.append(f"Slug '{slug}' already exists in marketplace")
                    break

        return errors


# --- Helper functions ---


def _get_miesc_version() -> str:
    """Get the current MIESC version."""
    try:
        from miesc import __version__

        return __version__
    except ImportError:
        pass
    try:
        import importlib.metadata

        return importlib.metadata.version("miesc")
    except Exception:
        return "5.1.0"


def _parse_version(version_str: str) -> tuple:
    """Parse version string to comparable tuple."""
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts[:3])
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _version_in_range(
    version: str,
    min_version: Optional[str],
    max_version: Optional[str],
) -> bool:
    """Check if version is within [min_version, max_version] range."""
    v = _parse_version(version)
    if min_version:
        if v < _parse_version(min_version):
            return False
    if max_version:
        if v > _parse_version(max_version):
            return False
    return True


def _slugify(name: str) -> str:
    """Convert a name to a URL-friendly slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug


def _compute_relevance(
    plugin: MarketplacePlugin,
    query_lower: str,
    query_words: List[str],
) -> float:
    """Compute search relevance score for a plugin."""
    score = 0.0
    slug_lower = plugin.slug.lower()
    name_lower = plugin.name.lower()
    desc_lower = plugin.description.lower()
    tags_lower = [t.lower() for t in plugin.tags]
    author_lower = plugin.author.lower()

    # Exact slug match
    if query_lower == slug_lower:
        score += 10.0
    elif query_lower in slug_lower:
        score += 8.0

    # Name matching
    if query_lower == name_lower:
        score += 10.0
    elif query_lower in name_lower:
        score += 6.0
    else:
        for word in query_words:
            if word in name_lower:
                score += 3.0

    # Tag matching
    for word in query_words:
        if word in tags_lower:
            score += 4.0

    # Description matching
    for word in query_words:
        if word in desc_lower:
            score += 2.0

    # Author matching
    if query_lower in author_lower:
        score += 2.0

    # Boost verified plugins
    if plugin.verification_status == VerificationStatus.VERIFIED:
        score *= 1.2

    return score

"""
MIESC CLI - Plugins Commands

Commands for managing MIESC detector plugins.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import logging
from pathlib import Path

import click

from miesc import __version__ as VERSION
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    info,
    print_banner,
    success,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree

logger = logging.getLogger(__name__)


@click.group()
def plugins():
    """Manage MIESC detector plugins."""
    pass


@plugins.command("list")
@click.option("--all", "-a", "show_all", is_flag=True, help="Show disabled plugins too")
def plugins_list(show_all):
    """List installed plugins."""
    print_banner()

    try:
        from miesc.plugins import CompatibilityStatus, PluginManager
    except ImportError:
        error("Plugin system not available")
        return

    manager = PluginManager()
    installed_plugins = manager.list_installed(include_disabled=show_all)

    if not installed_plugins:
        info("No plugins installed")
        info("Install plugins with: miesc plugins install <package>")
        return

    # Separate local and PyPI plugins for display
    local_plugins = [p for p in installed_plugins if p.local]
    pypi_plugins = [p for p in installed_plugins if not p.local]

    # Count compatibility issues
    incompatible_count = sum(
        1
        for p in installed_plugins
        if p.compatibility and p.compatibility.status == CompatibilityStatus.INCOMPATIBLE
    )

    if RICH_AVAILABLE:
        table = Table(title="Installed Plugins")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Compat")
        table.add_column("Detectors", justify="right")
        table.add_column("Description")

        for plugin in installed_plugins:
            status = "[green]enabled[/green]" if plugin.enabled else "[red]disabled[/red]"
            plugin_type = "[yellow]local[/yellow]" if plugin.local else "PyPI"

            # Compatibility status
            if plugin.compatibility:
                if plugin.compatibility.status == CompatibilityStatus.COMPATIBLE:
                    compat_str = "[green]ok[/green]"
                elif plugin.compatibility.status == CompatibilityStatus.INCOMPATIBLE:
                    compat_str = "[red]incompatible[/red]"
                elif plugin.compatibility.status == CompatibilityStatus.WARNING:
                    compat_str = "[yellow]warning[/yellow]"
                else:
                    compat_str = "[dim]unknown[/dim]"
            else:
                compat_str = "[dim]-[/dim]"

            table.add_row(
                plugin.package,
                plugin.version,
                plugin_type,
                status,
                compat_str,
                str(plugin.detector_count),
                (
                    plugin.description[:30] + "..."
                    if len(plugin.description) > 30
                    else plugin.description
                ),
            )
        console.print(table)

        if local_plugins:
            info(f"Local plugins directory: {manager.LOCAL_PLUGINS_DIR}")

        if incompatible_count > 0:
            warning(
                f"{incompatible_count} plugin(s) may be incompatible with MIESC {manager._miesc_version}"
            )
            info("Run 'miesc plugins info <name>' for compatibility details")
    else:
        print("\nInstalled Plugins:")  # noqa: T201
        for plugin in installed_plugins:
            status = "enabled" if plugin.enabled else "disabled"
            local_marker = " (local)" if plugin.local else ""
            compat_marker = ""
            if (
                plugin.compatibility
                and plugin.compatibility.status == CompatibilityStatus.INCOMPATIBLE
            ):
                compat_marker = " [INCOMPATIBLE]"
            elif (
                plugin.compatibility and plugin.compatibility.status == CompatibilityStatus.WARNING
            ):
                compat_marker = " [warning]"
            print(  # noqa: T201
                f"  {plugin.package} v{plugin.version}{local_marker}{compat_marker} - {status} ({plugin.detector_count} detectors)"
            )

        if local_plugins:
            print(f"\nLocal plugins directory: {manager.LOCAL_PLUGINS_DIR}")  # noqa: T201

        if incompatible_count > 0:
            print(  # noqa: T201
                f"\nWarning: {incompatible_count} plugin(s) may be incompatible with MIESC {manager._miesc_version}"
            )

    success(
        f"{len(installed_plugins)} plugins installed ({len(local_plugins)} local, {len(pypi_plugins)} PyPI)"
    )


@plugins.command("install")
@click.argument("package")
@click.option("--upgrade", "-U", is_flag=True, help="Upgrade if already installed")
@click.option("--force", "-f", is_flag=True, help="Force install even if incompatible")
@click.option("--no-check", is_flag=True, help="Skip compatibility check")
def plugins_install(package, upgrade, force, no_check):
    """Install a plugin from PyPI.

    The package name can be with or without the 'miesc-' prefix.
    Compatibility with current MIESC version is checked before installation.

    Examples:

      miesc plugins install miesc-defi-detectors

      miesc plugins install defi-detectors

      miesc plugins install my-plugin -U

      miesc plugins install old-plugin --force
    """
    print_banner()

    try:
        from miesc.plugins import CompatibilityStatus, PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()

    # Try to resolve marketplace slug to PyPI package name
    if not package.startswith("miesc-"):
        resolved = manager.resolve_marketplace_slug(package)
        if resolved:
            info(f"Resolved marketplace plugin '{package}' -> {resolved}")
            package = resolved

    # Check compatibility first if not skipped
    if not no_check and not force:
        info(f"Checking compatibility for {package}...")
        compat, version = manager.check_pypi_compatibility(package)

        if compat.status == CompatibilityStatus.INCOMPATIBLE:
            error(f"Plugin {package} is incompatible: {compat.message}")
            info("Use --force to install anyway, or --no-check to skip validation")
            raise SystemExit(1)
        elif compat.status == CompatibilityStatus.WARNING:
            warning(f"Compatibility warning: {compat.message}")
        elif compat.status == CompatibilityStatus.UNKNOWN and version is None:
            warning(f"Package {package} not found on PyPI")

    info(f"Installing {package}...")

    ok, message = manager.install(
        package,
        upgrade=upgrade,
        check_compatibility=False,  # Already checked above
        force=force,
    )

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("uninstall")
@click.argument("package")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def plugins_uninstall(package, yes):
    """Uninstall a plugin.

    Examples:

      miesc plugins uninstall miesc-defi-detectors

      miesc plugins uninstall defi-detectors -y
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    if not yes:
        if not click.confirm(f"Uninstall {package}?"):
            info("Cancelled")
            return

    manager = PluginManager()

    info(f"Uninstalling {package}...")

    ok, message = manager.uninstall(package)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("enable")
@click.argument("plugin_name")
def plugins_enable(plugin_name):
    """Enable a disabled plugin.

    Examples:

      miesc plugins enable miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()
    ok, message = manager.enable(plugin_name)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("disable")
@click.argument("plugin_name")
def plugins_disable(plugin_name):
    """Disable a plugin without uninstalling.

    Examples:

      miesc plugins disable miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()
    ok, message = manager.disable(plugin_name)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("info")
@click.argument("plugin_name")
def plugins_info(plugin_name):
    """Show detailed information about a plugin.

    Examples:

      miesc plugins info miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import CompatibilityStatus, PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()
    plugin = manager.get_plugin_info(plugin_name)

    if not plugin:
        error(f"Plugin not found: {plugin_name}")
        return

    # Compatibility display
    if plugin.compatibility:
        compat = plugin.compatibility
        if compat.status == CompatibilityStatus.COMPATIBLE:
            compat_str = "[green]Compatible[/green]"
            compat_plain = "Compatible"
        elif compat.status == CompatibilityStatus.INCOMPATIBLE:
            compat_str = f"[red]Incompatible[/red] - {compat.message}"
            compat_plain = f"Incompatible - {compat.message}"
        elif compat.status == CompatibilityStatus.WARNING:
            compat_str = f"[yellow]Warning[/yellow] - {compat.message}"
            compat_plain = f"Warning - {compat.message}"
        else:
            compat_str = "[dim]Unknown[/dim]"
            compat_plain = "Unknown"
    else:
        compat_str = "[dim]Not checked[/dim]"
        compat_plain = "Not checked"

    # Version requirements
    requires_miesc = plugin.requires_miesc or "any"
    requires_python = plugin.requires_python or "any"

    if RICH_AVAILABLE:
        panel_content = f"""[bold cyan]Package:[/bold cyan] {plugin.package}
[bold cyan]Version:[/bold cyan] {plugin.version}
[bold cyan]Status:[/bold cyan] {'[green]Enabled[/green]' if plugin.enabled else '[red]Disabled[/red]'}
[bold cyan]Author:[/bold cyan] {plugin.author or 'N/A'}
[bold cyan]Description:[/bold cyan] {plugin.description or 'N/A'}
[bold cyan]Detectors:[/bold cyan] {plugin.detector_count}
[bold cyan]Local:[/bold cyan] {'Yes' if plugin.local else 'No'}

[bold]Version Requirements:[/bold]
  MIESC: {requires_miesc}
  Python: {requires_python}

[bold]Compatibility:[/bold] {compat_str}
[dim](Current MIESC: {manager._miesc_version})[/dim]

[bold]Registered Detectors:[/bold]
{chr(10).join('  - ' + d for d in plugin.detectors) if plugin.detectors else '  (none)'}
"""
        console.print(Panel(panel_content, title=f"Plugin: {plugin.name}", border_style="cyan"))
    else:
        print(f"\n=== {plugin.name} ===")  # noqa: T201
        print(f"Package: {plugin.package}")  # noqa: T201
        print(f"Version: {plugin.version}")  # noqa: T201
        print(f"Status: {'Enabled' if plugin.enabled else 'Disabled'}")  # noqa: T201
        print(f"Author: {plugin.author or 'N/A'}")  # noqa: T201
        print(f"Detectors: {plugin.detector_count}")  # noqa: T201
        print("\nVersion Requirements:")  # noqa: T201
        print(f"  MIESC: {requires_miesc}")  # noqa: T201
        print(f"  Python: {requires_python}")  # noqa: T201
        print(f"\nCompatibility: {compat_plain}")  # noqa: T201
        print(f"(Current MIESC: {manager._miesc_version})")  # noqa: T201
        if plugin.detectors:
            print("\nRegistered Detectors:")  # noqa: T201
            for d in plugin.detectors:
                print(f"  - {d}")  # noqa: T201


@plugins.command("create")
@click.argument("name")
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory")
@click.option("--description", "-d", type=str, default="", help="Plugin description")
@click.option("--author", "-a", type=str, default="", help="Author name")
def plugins_create(name, output, description, author):
    """Create a new plugin project scaffold.

    Creates a complete plugin project structure with:
    - pyproject.toml with entry points
    - Detector class template
    - Test file template
    - README.md

    Examples:

      miesc plugins create my-detector

      miesc plugins create flash-loan-detector -o ./plugins -d "Flash loan detector"
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()

    info(f"Creating plugin scaffold for '{name}'...")

    try:
        plugin_path = manager.create_plugin_scaffold(
            name=name,
            output_dir=Path(output),
            description=description,
            author=author,
        )
        success(f"Created plugin at: {plugin_path}")
        info("")
        info("Next steps:")
        info(f"  cd {plugin_path}")
        info("  pip install -e .")
        info("  # Edit the detector in detectors.py")
        info("  miesc plugins list  # Verify plugin is registered")
    except Exception as e:
        error(f"Failed to create plugin: {e}")
        raise SystemExit(1) from e


@plugins.command("search")
@click.argument("query")
@click.option("--timeout", "-t", type=int, default=10, help="Request timeout in seconds")
@click.option("--marketplace-only", is_flag=True, help="Search marketplace only")
@click.option("--pypi-only", is_flag=True, help="Search PyPI only")
def plugins_search(query, timeout, marketplace_only, pypi_only):
    """Search for MIESC plugins.

    Searches the MIESC marketplace and PyPI for matching plugins.
    Results include source, package name, version, and description.

    Examples:

      miesc plugins search defi

      miesc plugins search flash-loan --marketplace-only

      miesc plugins search reentrancy --pypi-only
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()
    all_results = []

    # Search marketplace first
    if not pypi_only:
        info(f"Searching marketplace for '{query}'...")
        mp_results = manager.search_marketplace(query)
        all_results.extend(mp_results)

    # Search PyPI
    if not marketplace_only:
        info(f"Searching PyPI for '{query}'...")
        pypi_results = manager.search_pypi(query, timeout=timeout)
        # Mark PyPI results and avoid duplicates
        seen_packages = {r["pypi_package"] for r in all_results if "pypi_package" in r}
        for pkg in pypi_results:
            if pkg["name"] not in seen_packages:
                pkg["source"] = "pypi"
                pkg["verification_status"] = ""
                all_results.append(pkg)

    if not all_results:
        info(f"No plugins found matching '{query}'")
        info("")
        info("Tips:")
        info("  - Try a different search term")
        info("  - Browse the marketplace: miesc plugins marketplace")
        info("  - Create your own plugin: miesc plugins create <name>")
        return

    if RICH_AVAILABLE:
        table = Table(title=f"Found {len(all_results)} plugin(s)")
        table.add_column("Source", style="dim")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Description")

        for pkg in all_results:
            desc = pkg.get("description", "")
            if len(desc) > 45:
                desc = desc[:42] + "..."
            source = pkg.get("source", "pypi")
            status = pkg.get("verification_status", "")
            name = pkg.get("pypi_package", pkg.get("name", ""))
            table.add_row(source, name, pkg.get("version", ""), status, desc)

        console.print(table)
        console.print("")
        info("Install with: miesc plugins install <package-name>")
    else:
        print(f"\nFound {len(all_results)} plugin(s) matching '{query}':\n")  # noqa: T201
        for pkg in all_results:
            desc = pkg.get("description", "")
            if len(desc) > 50:
                desc = desc[:47] + "..."
            source = pkg.get("source", "pypi")
            name = pkg.get("pypi_package", pkg.get("name", ""))
            print(f"  [{source}] {name} (v{pkg.get('version', '?')})")  # noqa: T201
            if desc:
                print(f"    {desc}")  # noqa: T201
            print()  # noqa: T201
        print("Install with: miesc plugins install <package-name>")  # noqa: T201


@plugins.command("path")
@click.option("--create", "-c", is_flag=True, help="Create the directory if it doesn't exist")
def plugins_path(create):
    """Show the local plugins directory path.

    Local plugins can be placed in this directory for automatic discovery
    without requiring PyPI installation.

    Examples:

      miesc plugins path

      miesc plugins path --create
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError as e:
        error("Plugin system not available")
        raise SystemExit(1) from e

    manager = PluginManager()
    plugins_dir = manager.LOCAL_PLUGINS_DIR

    if create:
        plugins_dir = manager.ensure_local_plugins_dir()
        success(f"Local plugins directory created: {plugins_dir}")
    else:
        info(f"Local plugins directory: {plugins_dir}")
        if plugins_dir.exists():
            success("Directory exists")
            # Count plugins
            plugin_count = sum(
                1 for d in plugins_dir.iterdir() if d.is_dir() and not d.name.startswith(".")
            )
            if plugin_count:
                info(f"Contains {plugin_count} plugin(s)")
        else:
            info("Directory does not exist yet")
            info("Use --create to create it, or it will be created automatically")

    info("")
    info("To add a local plugin:")
    info(f"  1. Copy your plugin to: {plugins_dir}/<plugin-name>/")
    info("  2. Ensure it has a detectors.py or <package>/detectors.py file")
    info("  3. Run 'miesc plugins list' to verify it's detected")


@plugins.command("new")
@click.argument("name")
@click.option(
    "--type",
    "-t",
    "plugin_type",
    type=click.Choice(["detector", "adapter", "reporter", "transformer"]),
    default="detector",
    help="Plugin type",
)
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory")
@click.option("--description", "-d", type=str, default="", help="Plugin description")
@click.option("--author", "-a", type=str, default="", help="Author name")
@click.option("--email", "-e", type=str, default="", help="Author email")
def plugins_new(name, plugin_type, output, description, author, email):
    """Create a new plugin from template.

    Generates a complete plugin project structure with:
    - pyproject.toml with entry points
    - Plugin implementation file
    - Test files
    - README.md

    \b
    Examples:
        miesc plugins new my-detector
        miesc plugins new flash-loan-detector -t detector -d "Flash loan detector"
        miesc plugins new custom-reporter -t reporter -o ./plugins
    """
    print_banner()

    try:
        from src.plugins import PluginTemplateGenerator, PluginType
    except ImportError as e:
        error("Plugin template system not available")
        raise SystemExit(1) from e

    # Map type string to enum
    type_map = {
        "detector": PluginType.DETECTOR,
        "adapter": PluginType.ADAPTER,
        "reporter": PluginType.REPORTER,
        "transformer": PluginType.TRANSFORMER,
    }
    ptype = type_map[plugin_type]

    info(f"Creating {plugin_type} plugin: {name}")

    try:
        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name=name,
            plugin_type=ptype,
            output_dir=Path(output),
            description=description or f"MIESC {plugin_type} plugin",
            author=author,
            email=email,
        )

        success(f"Plugin created: {plugin_path}")

        if RICH_AVAILABLE:
            tree = Tree(f"[bold cyan]{plugin_path.name}[/bold cyan]")
            for item in sorted(plugin_path.iterdir()):
                if item.is_dir():
                    branch = tree.add(f"[bold]{item.name}/[/bold]")
                    for subitem in sorted(item.iterdir()):
                        branch.add(subitem.name)
                else:
                    tree.add(item.name)
            console.print(tree)
        else:
            print("\nFiles created:")  # noqa: T201
            for f in sorted(plugin_path.rglob("*")):
                if f.is_file():
                    print(f"  {f.relative_to(plugin_path)}")  # noqa: T201

        print("")  # noqa: T201
        info("Next steps:")
        print(f"  1. cd {plugin_path}")  # noqa: T201
        print("  2. Edit the plugin implementation in plugin.py")  # noqa: T201
        print("  3. Run tests: pytest")  # noqa: T201
        print("  4. Install: pip install -e .")  # noqa: T201
        print("  5. Verify: miesc plugins list")  # noqa: T201

    except Exception as e:
        error(f"Failed to create plugin: {e}")
        raise SystemExit(1) from e


@plugins.command("runtime")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed info")
def plugins_runtime(verbose):
    """Show plugins loaded in the runtime registry.

    Displays plugins that have been loaded into memory via the
    new plugin system (src/plugins).

    \b
    Examples:
        miesc plugins runtime
        miesc plugins runtime -v
    """
    print_banner()

    try:
        from src.plugins import PluginType, get_registry
    except ImportError as e:
        error("Plugin runtime system not available")
        raise SystemExit(1) from e

    registry = get_registry()
    plugins_list = registry.list_plugins()

    if not plugins_list:
        info("No plugins loaded in runtime registry")
        info("Load plugins with: miesc plugins load <file>")
        return

    if RICH_AVAILABLE:
        table = Table(title="Runtime Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Type")
        table.add_column("Status")
        if verbose:
            table.add_column("Source")

        for entry in plugins_list:
            status = "[green]enabled[/green]" if entry.enabled else "[red]disabled[/red]"
            row = [
                entry.name,
                entry.version,
                entry.plugin_type.value,
                status,
            ]
            if verbose:
                row.append(entry.source[:40] + "..." if len(entry.source) > 40 else entry.source)
            table.add_row(*row)

        console.print(table)
    else:
        print("\nRuntime Plugins:")  # noqa: T201
        for entry in plugins_list:
            status = "enabled" if entry.enabled else "disabled"
            print(f"  {entry.name} v{entry.version} ({entry.plugin_type.value}) - {status}")  # noqa: T201

    stats = registry.get_stats()
    success(f"{stats['total']} plugins loaded ({stats['enabled']} enabled)")


@plugins.command("load")
@click.argument("plugin_path", type=click.Path(exists=True))
@click.option("--enable/--no-enable", default=True, help="Enable plugin after loading")
def plugins_load(plugin_path, enable):
    """Load a plugin file into the runtime registry.

    Loads a Python file containing a plugin class following
    the MIESC plugin protocol.

    \b
    Examples:
        miesc plugins load ./my_plugin.py
        miesc plugins load /path/to/detector.py --no-enable
    """
    print_banner()

    try:
        from src.plugins import (
            PluginContext,
            PluginLoader,
            get_registry,
        )
    except ImportError as e:
        error("Plugin runtime system not available")
        raise SystemExit(1) from e

    info(f"Loading plugin from: {plugin_path}")

    try:
        loader = PluginLoader()
        loaded_plugins = loader.load_plugin_file(plugin_path)

        if not loaded_plugins:
            warning("No plugin classes found in file")
            return

        # Create context
        context = PluginContext(
            miesc_version=VERSION,
            config={},
            data_dir=Path.home() / ".miesc" / "data",
            cache_dir=Path.home() / ".miesc" / "cache",
        )

        registry = get_registry()

        for loaded in loaded_plugins:
            # Initialize and register
            instance = loader.load_and_initialize(loaded, context)
            entry = registry.register(loaded, enabled=enable)

            success(f"Loaded: {entry.name} v{entry.version} ({entry.plugin_type.value})")

        info(f"Loaded {len(loaded_plugins)} plugin(s)")
        info("View with: miesc plugins runtime")

    except Exception as e:
        error(f"Failed to load plugin: {e}")
        logger.exception("Plugin load error")
        raise SystemExit(1) from e


@plugins.command("marketplace")
@click.option("--type", "-t", "plugin_type", default=None,
              type=click.Choice(["detector", "adapter", "reporter", "transformer"]),
              help="Filter by plugin type")
@click.option("--tag", multiple=True, help="Filter by tag")
@click.option("--verified-only", is_flag=True, help="Show only verified plugins")
@click.option("--refresh", is_flag=True, help="Force refresh from remote")
@click.option("--page", type=int, default=1, help="Page number")
def plugins_marketplace(plugin_type, tag, verified_only, refresh, page):
    """Browse the MIESC plugin marketplace.

    Shows available plugins from the remote marketplace index hosted
    on GitHub. Plugins are community-submitted and reviewed via PR.

    \b
    Examples:
        miesc plugins marketplace
        miesc plugins marketplace --type detector
        miesc plugins marketplace --tag defi --verified-only
        miesc plugins marketplace --refresh
    """
    print_banner()

    try:
        from src.plugins.marketplace import MarketplaceClient, VerificationStatus
    except ImportError as e:
        error("Marketplace module not available")
        raise SystemExit(1) from e

    client = MarketplaceClient()

    try:
        verification = None
        if verified_only:
            verification = VerificationStatus.VERIFIED

        mp_plugins = client.browse(
            plugin_type=plugin_type,
            verification_status=verification,
            page=page,
        )

        # Apply tag filter manually if specified
        if tag:
            tag_set = set(tag)
            mp_plugins = [p for p in mp_plugins if tag_set.intersection(p.tags)]

        if not mp_plugins:
            info("No plugins found matching your filters.")
            info("Try: miesc plugins marketplace --refresh")
            return

        if RICH_AVAILABLE:
            table = Table(title=f"MIESC Plugin Marketplace (page {page})")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Status", style="yellow")
            table.add_column("Author")
            table.add_column("Description")

            status_styles = {
                VerificationStatus.VERIFIED: "[green]verified[/green]",
                VerificationStatus.COMMUNITY: "[yellow]community[/yellow]",
                VerificationStatus.EXPERIMENTAL: "[dim]experimental[/dim]",
            }

            for p in mp_plugins:
                desc = p.description
                if len(desc) > 40:
                    desc = desc[:37] + "..."
                status = status_styles.get(p.verification_status, p.verification_status.value)
                table.add_row(p.name, p.version, p.plugin_type, status, p.author, desc)

            console.print(table)
            console.print("")
        else:
            print(f"\nMIESC Plugin Marketplace (page {page}):\n")  # noqa: T201
            for p in mp_plugins:
                desc = p.description
                if len(desc) > 50:
                    desc = desc[:47] + "..."
                print(f"  {p.name} v{p.version} [{p.plugin_type}] ({p.verification_status.value})")  # noqa: T201
                print(f"    by {p.author} - {desc}")  # noqa: T201
                print()  # noqa: T201

        info("Install with: miesc plugins install <slug>")
        info("More details: miesc plugins info <slug>")

    except Exception as e:
        error(f"Failed to browse marketplace: {e}")
        raise SystemExit(1) from e


@plugins.command("submit")
@click.option("--name", prompt="Plugin display name", help="Plugin display name")
@click.option("--package", prompt="PyPI package name (miesc-...)", help="PyPI package name")
@click.option("--version", "pkg_version", prompt="Version", help="Plugin version")
@click.option("--type", "plugin_type", prompt="Plugin type",
              type=click.Choice(["detector", "adapter", "reporter", "transformer"]),
              help="Plugin type")
@click.option("--description", prompt="Description", help="Plugin description")
@click.option("--author", prompt="Author name", help="Author name")
@click.option("--open-pr", is_flag=True, help="Open GitHub PR creation page")
def plugins_submit(name, package, pkg_version, plugin_type, description, author, open_pr):
    """Generate a marketplace submission entry.

    Creates a JSON entry for submitting your plugin to the MIESC marketplace.
    Copy the output into a PR to the MIESC repository.

    \b
    Examples:
        miesc plugins submit
        miesc plugins submit --name "My Detector" --package miesc-my-detector \\
            --version 1.0.0 --type detector --description "Detects things" \\
            --author "Dev"
    """
    print_banner()

    try:
        from src.plugins.marketplace import MarketplaceClient
    except ImportError as e:
        error("Marketplace module not available")
        raise SystemExit(1) from e

    client = MarketplaceClient()

    entry = client.generate_submission(
        name=name,
        pypi_package=package,
        version=pkg_version,
        plugin_type=plugin_type,
        description=description,
        author=author,
    )

    errors = client.validate_submission(entry)
    if errors:
        error("Submission validation failed:")
        for err in errors:
            error(f"  - {err}")
        raise SystemExit(1)

    entry_json = json.dumps(entry, indent=2)

    success("Submission entry generated:")
    print(f"\n{entry_json}\n")  # noqa: T201
    info("To submit to the marketplace:")
    info("  1. Fork https://github.com/fboiero/MIESC")
    info("  2. Add this entry to data/marketplace/marketplace-index.json")
    info("  3. Open a Pull Request")

    if open_pr:
        import webbrowser
        pr_url = "https://github.com/fboiero/MIESC/edit/main/data/marketplace/marketplace-index.json"
        info(f"Opening {pr_url} ...")
        webbrowser.open(pr_url)

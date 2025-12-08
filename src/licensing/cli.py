"""
CLI para administración de licencias MIESC.
Uso: python -m src.licensing.cli [comando] [opciones]
"""

import click
from datetime import datetime
from tabulate import tabulate

from .license_manager import LicenseManager
from .quota_checker import QuotaChecker
from .models import LicenseStatus, PlanType
from .key_generator import generate_license_key


@click.group()
@click.pass_context
def cli(ctx):
    """MIESC License Manager - Administración de licencias."""
    ctx.ensure_object(dict)
    ctx.obj["manager"] = LicenseManager()
    ctx.obj["quota"] = QuotaChecker()


@cli.command()
@click.option("--email", "-e", required=True, help="Email del propietario")
@click.option(
    "--plan",
    "-p",
    type=click.Choice(["FREE", "STARTER", "PRO", "ENTERPRISE"]),
    default="FREE",
    help="Tipo de plan"
)
@click.option("--organization", "-o", help="Organización")
@click.option("--expires", "-x", type=int, help="Días hasta expiración (vacío = perpetua)")
@click.option("--notes", "-n", help="Notas adicionales")
@click.pass_context
def generate(ctx, email, plan, organization, expires, notes):
    """Genera una nueva licencia."""
    manager = ctx.obj["manager"]

    plan_type = PlanType[plan]
    license = manager.create_license(
        email=email,
        plan=plan_type,
        organization=organization,
        expires_days=expires,
        notes=notes,
    )

    click.echo("\n" + "=" * 60)
    click.echo("LICENCIA GENERADA")
    click.echo("=" * 60)
    click.echo(f"\nClave: {click.style(license.license_key, fg='green', bold=True)}")
    click.echo(f"Email: {license.email}")
    click.echo(f"Plan: {license.plan.value}")
    if license.organization:
        click.echo(f"Organización: {license.organization}")
    click.echo(f"Estado: {license.status.value}")
    click.echo(f"Creada: {license.created_at.strftime('%Y-%m-%d %H:%M')}")
    if license.expires_at:
        click.echo(f"Expira: {license.expires_at.strftime('%Y-%m-%d')}")
    else:
        click.echo("Expira: Nunca (perpetua)")
    click.echo("\n" + "=" * 60)


@cli.command()
@click.argument("key")
@click.pass_context
def validate(ctx, key):
    """Valida una clave de licencia."""
    manager = ctx.obj["manager"]
    license = manager.validate(key)

    if license:
        click.echo(click.style("\nLICENCIA VÁLIDA", fg="green", bold=True))
        click.echo(f"Plan: {license.plan.value}")
        click.echo(f"Email: {license.email}")
        if license.days_until_expiry is not None:
            click.echo(f"Días restantes: {license.days_until_expiry}")
    else:
        click.echo(click.style("\nLICENCIA INVÁLIDA O EXPIRADA", fg="red", bold=True))


@cli.command("list")
@click.option(
    "--status", "-s",
    type=click.Choice(["active", "expired", "suspended", "revoked"]),
    help="Filtrar por estado"
)
@click.option(
    "--plan", "-p",
    type=click.Choice(["FREE", "STARTER", "PRO", "ENTERPRISE"]),
    help="Filtrar por plan"
)
@click.option("--email", "-e", help="Filtrar por email")
@click.pass_context
def list_licenses(ctx, status, plan, email):
    """Lista todas las licencias."""
    manager = ctx.obj["manager"]

    status_filter = LicenseStatus[status.upper()] if status else None
    plan_filter = PlanType[plan] if plan else None

    licenses = manager.list_licenses(
        status=status_filter,
        plan=plan_filter,
        email=email,
    )

    if not licenses:
        click.echo("No se encontraron licencias.")
        return

    table_data = []
    for lic in licenses:
        expires = lic.expires_at.strftime("%Y-%m-%d") if lic.expires_at else "Perpetua"
        status_color = "green" if lic.is_active else "red"
        table_data.append([
            lic.license_key[:20] + "...",
            lic.email[:25],
            lic.plan.value,
            click.style(lic.status.value, fg=status_color),
            expires,
        ])

    headers = ["Clave", "Email", "Plan", "Estado", "Expira"]
    click.echo("\n" + tabulate(table_data, headers=headers, tablefmt="simple"))
    click.echo(f"\nTotal: {len(licenses)} licencia(s)")


@cli.command()
@click.argument("key")
@click.pass_context
def revoke(ctx, key):
    """Revoca una licencia."""
    manager = ctx.obj["manager"]

    if manager.revoke_license(key):
        click.echo(click.style(f"\nLicencia revocada: {key}", fg="yellow"))
    else:
        click.echo(click.style(f"\nError: No se pudo revocar la licencia", fg="red"))


@cli.command()
@click.argument("key")
@click.pass_context
def suspend(ctx, key):
    """Suspende una licencia temporalmente."""
    manager = ctx.obj["manager"]

    if manager.suspend_license(key):
        click.echo(click.style(f"\nLicencia suspendida: {key}", fg="yellow"))
    else:
        click.echo(click.style(f"\nError: No se pudo suspender la licencia", fg="red"))


@cli.command()
@click.argument("key")
@click.pass_context
def reactivate(ctx, key):
    """Reactiva una licencia suspendida."""
    manager = ctx.obj["manager"]

    if manager.reactivate_license(key):
        click.echo(click.style(f"\nLicencia reactivada: {key}", fg="green"))
    else:
        click.echo(click.style(f"\nError: No se pudo reactivar la licencia", fg="red"))


@cli.command()
@click.argument("key")
@click.pass_context
def usage(ctx, key):
    """Muestra el uso de una licencia."""
    manager = ctx.obj["manager"]
    quota = ctx.obj["quota"]

    license = manager.get_license(key)
    if not license:
        click.echo(click.style(f"\nLicencia no encontrada: {key}", fg="red"))
        return

    usage_info = quota.get_usage(license)

    click.echo("\n" + "=" * 60)
    click.echo(f"USO DE LICENCIA: {key}")
    click.echo("=" * 60)
    click.echo(f"\nPlan: {usage_info['plan']}")
    click.echo(f"Mes actual: {usage_info['month']}")
    click.echo(f"Auditorías usadas: {usage_info['audits_used']}")
    click.echo(f"Límite: {usage_info['audits_limit']}")
    click.echo(f"Restantes: {usage_info['audits_remaining']}")
    if usage_info['last_audit_at']:
        click.echo(f"Última auditoría: {usage_info['last_audit_at']}")
    click.echo(f"\nHerramientas permitidas:")
    for tool in usage_info['allowed_tools']:
        click.echo(f"  - {tool}")
    click.echo(f"\nIA habilitada: {'Sí' if usage_info['ai_enabled'] else 'No'}")
    click.echo(f"Tamaño máx contrato: {usage_info['max_contract_size_kb']}KB")
    click.echo("=" * 60)


@cli.command()
@click.pass_context
def stats(ctx):
    """Muestra estadísticas de licencias."""
    manager = ctx.obj["manager"]
    stats = manager.get_stats()

    click.echo("\n" + "=" * 60)
    click.echo("ESTADÍSTICAS DE LICENCIAS")
    click.echo("=" * 60)
    click.echo(f"\nTotal: {stats['total']}")
    click.echo(f"Activas: {click.style(str(stats['active']), fg='green')}")
    click.echo(f"Expiradas: {click.style(str(stats['expired']), fg='yellow')}")
    click.echo(f"Suspendidas: {click.style(str(stats['suspended']), fg='yellow')}")
    click.echo(f"Revocadas: {click.style(str(stats['revoked']), fg='red')}")
    click.echo("\nPor plan:")
    for plan, count in stats['by_plan'].items():
        click.echo(f"  {plan}: {count}")
    click.echo("=" * 60)


@cli.command()
@click.argument("key")
@click.option(
    "--plan", "-p",
    type=click.Choice(["FREE", "STARTER", "PRO", "ENTERPRISE"]),
    help="Nuevo plan"
)
@click.option("--extend-days", "-x", type=int, help="Extender días")
@click.pass_context
def update(ctx, key, plan, extend_days):
    """Actualiza una licencia existente."""
    manager = ctx.obj["manager"]

    license = manager.get_license(key)
    if not license:
        click.echo(click.style(f"\nLicencia no encontrada: {key}", fg="red"))
        return

    new_plan = PlanType[plan] if plan else None
    new_expires = None
    if extend_days:
        from datetime import timedelta
        base = license.expires_at or datetime.utcnow()
        new_expires = base + timedelta(days=extend_days)

    updated = manager.update_license(
        key,
        plan=new_plan,
        expires_at=new_expires,
    )

    if updated:
        click.echo(click.style(f"\nLicencia actualizada: {key}", fg="green"))
        if new_plan:
            click.echo(f"Nuevo plan: {new_plan.value}")
        if new_expires:
            click.echo(f"Nueva expiración: {new_expires.strftime('%Y-%m-%d')}")
    else:
        click.echo(click.style(f"\nError actualizando licencia", fg="red"))


if __name__ == "__main__":
    cli()

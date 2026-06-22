"""`redeye doctor` -- health check for the active profile.

Returns 0 if the profile is operable, non-zero if any required backend
is missing credentials or otherwise unreachable.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from redeye.backends import BACKENDS
from redeye.config import load_profile


def run(*, console: Console, profile: str | None, no_network: bool) -> int:
    cfg = load_profile(profile)
    console.rule(f"[bold]redeye doctor[/bold] -- profile: {cfg.name}")

    required_backends = sorted({role.via for role in cfg.roles.values()})
    console.print(f"Profile uses backends: [cyan]{', '.join(required_backends)}[/cyan]\n")

    table = Table(title="Backend status")
    table.add_column("Backend")
    table.add_column("Credential")
    table.add_column("Reachable")
    table.add_column("Notes")

    overall_ok = True
    for backend_name in required_backends:
        factory = BACKENDS.get(backend_name)
        if factory is None:
            table.add_row(
                backend_name, "[red]unknown[/red]", "[red]FAIL[/red]", "no factory registered"
            )
            overall_ok = False
            continue
        try:
            backend = factory({})
            cred_ok = backend.has_credential()
            if no_network:
                reachable = cred_ok
                note = "skipped (--no-network)"
            else:
                reachable = backend.health_check() if cred_ok else False
                note = "" if reachable else "credential or endpoint failed"
            table.add_row(
                backend_name,
                "[green]OK[/green]" if cred_ok else "[red]MISSING[/red]",
                "[green]OK[/green]" if reachable else "[red]FAIL[/red]",
                note,
            )
            if not reachable:
                overall_ok = False
        except Exception as exc:  # noqa: BLE001
            table.add_row(backend_name, "[red]ERROR[/red]", "[red]FAIL[/red]", str(exc))
            overall_ok = False

    console.print(table)

    if overall_ok:
        console.print("\n[green]All required backends are operable.[/green]")
        return 0
    console.print(
        "\n[red]One or more backends failed.[/red] Run [cyan]redeye setup[/cyan] for guidance."
    )
    return 1

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from delegationflow.core.models import AssessmentResult

console = Console()


def render_accounts(accounts) -> None:
    table = Table(title="Unconstrained Delegation Accounts")
    table.add_column("Name", style="cyan")
    table.add_column("sAMAccountName")
    table.add_column("Enabled")
    table.add_column("SPN count", justify="right")
    table.add_column("Distinguished Name", overflow="fold")
    for account in accounts:
        table.add_row(
            account.name,
            account.sam_account_name or "-",
            str(account.enabled) if account.enabled is not None else "Unknown",
            str(len(account.service_principal_names)),
            account.dn,
        )
    console.print(table)
    console.print(f"[bold]Total accounts:[/bold] {len(accounts)}")


def render_result(result: AssessmentResult) -> None:
    console.print(Panel.fit(
        f"[bold]Server:[/bold] {result.server}\n"
        f"[bold]Base DN:[/bold] {result.base_dn}\n"
        f"[bold]Accounts:[/bold] {len(result.accounts)}\n"
        f"[bold]Findings:[/bold] {len(result.findings)}",
        title="DelegationFlow Assessment",
    ))
    table = Table()
    table.add_column("ID", style="dim")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Status")
    for finding in result.findings:
        color = {
            "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
            "LOW": "green", "INFO": "cyan",
        }[finding.severity.value]
        table.add_row(finding.finding_id, f"[{color}]{finding.severity.value}[/]", finding.title, finding.status)
    console.print(table)
    for finding in result.findings:
        console.print(f"\n[bold]{finding.finding_id} — {finding.title}[/bold]")
        console.print(finding.description)
        if finding.recommendations:
            console.print("[bold]Recommendations:[/bold]")
            for recommendation in finding.recommendations:
                console.print(f"  • {recommendation}")


def export_json(result: AssessmentResult, output_path: str) -> None:
    path = Path(output_path).expanduser()
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"[green]JSON assessment written to:[/green] {path}")

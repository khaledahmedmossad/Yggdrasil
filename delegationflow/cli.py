import builtins
import typer
from rich.console import Console

from delegationflow import __version__
from delegationflow.core.config import load_settings, obtain_password
from delegationflow.core.exceptions import (
    ConfigurationError, DirectoryConnectionError, DirectorySearchError,
)
from delegationflow.core.logging import configure_logging
from delegationflow.integrations.ldap_client import LDAPDirectoryClient
from delegationflow.modules.enumeration import enumerate_unconstrained
from delegationflow.modules.assessment import assess_accounts
from delegationflow.output.render import console, render_accounts, render_result, export_json
from delegationflow.output.html import export_html
from delegationflow.modules.delegation_modes import (
    enumerate_delegation_modes, enumerate_domain_controllers, enumerate_protected_users_group,
)
from delegationflow.modules.bloodhound import analyze_bloodhound_export
from delegationflow.modules.acl import audit_target_acl
from delegationflow.core.models import AssessmentResult, Finding, Severity
import json

app = typer.Typer(
    name="delegationflow",
    help=(
        "Active Directory delegation assessment with read-only commands and an "
        "opt-in authorized-lab exploit workflow."
    ),
    no_args_is_help=True,
    add_completion=False,
)
err_console = Console(stderr=True)


def _settings(config, server, port, use_ssl, base_dn, username, validate_tls):
    return load_settings(config, {
        "server": server, "port": port, "use_ssl": use_ssl,
        "base_dn": base_dn, "username": username, "validate_tls": validate_tls,
    })


def _run(config, server, port, use_ssl, base_dn, username, validate_tls, verbose, action):
    configure_logging(verbose)
    try:
        settings = _settings(config, server, port, use_ssl, base_dn, username, validate_tls)
        password = obtain_password()
        with LDAPDirectoryClient(settings, password) as client:
            if action == "check":
                console.print(f"[green]LDAP bind successful[/green] — {settings.server}:{settings.port}")
                console.print(f"Base DN: {settings.base_dn}")
                return 0
            accounts = enumerate_unconstrained(client, settings.base_dn, settings.page_size)
            if action == "enumerate":
                render_accounts(accounts)
                return 0
            result = assess_accounts(settings.server, settings.base_dn, accounts)
            render_result(result)
            return 0
    except ConfigurationError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        return 2
    except DirectoryConnectionError as exc:
        err_console.print(f"[red]Connection error:[/red] {exc}")
        return 3
    except DirectorySearchError as exc:
        err_console.print(f"[red]Directory search error:[/red] {exc}")
        return 4
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


_COMMON = dict(
    config=typer.Option(None, "--config", "-c", help="YAML configuration file (must not contain credentials)."),
    server=typer.Option(None, "--server", help="LDAP server hostname or IP."),
    port=typer.Option(None, "--port", min=1, max=65535, help="LDAP port; defaults to 389."),
    use_ssl=typer.Option(None, "--use-ssl/--no-use-ssl", help="Use LDAPS."),
    base_dn=typer.Option(None, "--base-dn", help="LDAP search base DN."),
    username=typer.Option(None, "--username", "-u", help="LDAP bind username."),
    validate_tls=typer.Option(None, "--validate-tls/--no-validate-tls", help="Validate LDAPS certificates."),
    verbose=typer.Option(False, "--verbose", "-v", help="Enable diagnostic logging."),
)


@app.command()
def check(
    config: str = _COMMON["config"], server: str = _COMMON["server"],
    port: int = _COMMON["port"], use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"], username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"], verbose: bool = _COMMON["verbose"],
):
    """Validate configuration, network connection, and LDAP bind."""
    raise typer.Exit(_run(config, server, port, use_ssl, base_dn, username, validate_tls, verbose, "check"))


@app.command()
def enumerate(
    config: str = _COMMON["config"], server: str = _COMMON["server"],
    port: int = _COMMON["port"], use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"], username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"], verbose: bool = _COMMON["verbose"],
):
    """Enumerate accounts configured for Unconstrained Delegation."""
    raise typer.Exit(_run(config, server, port, use_ssl, base_dn, username, validate_tls, verbose, "enumerate"))


@app.command()
def assess(
    config: str = _COMMON["config"], server: str = _COMMON["server"],
    port: int = _COMMON["port"], use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"], username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"], verbose: bool = _COMMON["verbose"],
    output: str | None = typer.Option(None, "--output", "-o", help="Optional JSON output path."),
    html_output: str | None = typer.Option(None, "--html", help="Optional HTML report path."),
):
    """Run enumeration and generate security findings."""
    configure_logging(verbose)
    try:
        settings = _settings(config, server, port, use_ssl, base_dn, username, validate_tls)
        password = obtain_password()
        with LDAPDirectoryClient(settings, password) as client:
            accounts = enumerate_unconstrained(client, settings.base_dn, settings.page_size)
        result = assess_accounts(settings.server, settings.base_dn, accounts)
        render_result(result)
        if output:
            export_json(result, output)
        if html_output:
            export_html(result, html_output)
            console.print(f"[green]HTML report written to:[/green] {html_output}")
        return
    except ConfigurationError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2)
    except DirectoryConnectionError as exc:
        err_console.print(f"[red]Connection error:[/red] {exc}")
        raise typer.Exit(3)
    except DirectorySearchError as exc:
        err_console.print(f"[red]Directory search error:[/red] {exc}")
        raise typer.Exit(4)



@app.command("full-audit")
def full_audit(
    config: str = _COMMON["config"], server: str = _COMMON["server"],
    port: int = _COMMON["port"], use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"], username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"], verbose: bool = _COMMON["verbose"],
    output: str = typer.Option("delegationflow-full-audit.json", "--output", "-o"),
    html_output: str = typer.Option("delegationflow-full-audit.html", "--html"),
):
    """Run read-only delegation-mode, DC, and Protected Users discovery."""
    configure_logging(verbose)
    try:
        settings = _settings(config, server, port, use_ssl, base_dn, username, validate_tls)
        password = obtain_password()
        with LDAPDirectoryClient(settings, password) as client:
            modes = enumerate_delegation_modes(client, settings.base_dn, settings.page_size)
            dcs = enumerate_domain_controllers(client, settings.base_dn, settings.page_size)
            protected = enumerate_protected_users_group(client, settings.base_dn, settings.page_size)
        unconstrained = []
        # Reuse the canonical parser so the existing finding model remains consistent.
        # Convert the returned directory records into the canonical assessment model.
        from delegationflow.core.models import DirectoryAccount
        for r in modes["unconstrained"]:
            unconstrained.append(DirectoryAccount(
                dn=r["dn"], name=r["name"], sam_account_name=r.get("sam_account_name"),
                object_classes=r.get("object_classes", []), user_account_control=r.get("uac"),
                enabled=r.get("enabled"), service_principal_names=r.get("spns", [])))
        from delegationflow.modules.assessment import assess_accounts
        result = assess_accounts(settings.server, settings.base_dn, unconstrained)
        extra_findings = []
        for mode, label in (("constrained", "Constrained Delegation configured"), ("rbcd", "Resource-Based Constrained Delegation configured")):
            for idx, item in builtins.enumerate(modes[mode], 1):
                extra_findings.append(Finding(
                    finding_id=f"DF-{mode.upper()}-{idx:04d}", title=label,
                    severity=Severity.MEDIUM, status="confirmed_configuration",
                    description="Delegation-related directory attributes were returned. Review service ownership, target scope, and effective permissions; configuration alone does not prove an exploitable path.",
                    evidence={"dn": item["dn"], "sam_account_name": item.get("sam_account_name"),
                              "allowed_to_delegate_to": item.get("allowed_to_delegate_to", []),
                              "rbcd_descriptor_present": item.get("rbcd_descriptor_present", False)},
                    recommendations=["Validate the business requirement and allowed targets.", "Review who can modify the delegating account or the target resource descriptor."]
                ))
        result.findings.extend(extra_findings)
        result.context = {"delegation_modes": modes, "domain_controllers": dcs,
                          "protected_users_group": protected,
                          "acl_analysis": {"status": "offline_import_supported", "hint": "Use `delegationflow bloodhound --directory <extracted-export-dir>` to correlate GenericWrite/GenericAll/WriteDacl/WriteOwner edges."}}
        export_json(result, output)
        export_html(result, html_output)
        render_result(result)
        console.print(f"[green]JSON:[/green] {output}  [green]HTML:[/green] {html_output}")
    except (ConfigurationError, DirectoryConnectionError, DirectorySearchError) as exc:
        err_console.print(f"[red]Full audit failed:[/red] {exc}")
        raise typer.Exit(2)


@app.command("bloodhound")
def bloodhound(
    directory: str = typer.Option(..., "--directory", "-d", help="Directory containing extracted BloodHound JSON exports."),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional JSON output path."),
    graph: str | None = typer.Option(None, "--graph", help="Optional Mermaid graph output path (.mmd)."),
):
    """Offline ACL edge analysis for BloodHound JSON exports; no AD connection."""
    try:
        report = analyze_bloodhound_export(directory)
        rendered = json.dumps(report, indent=2)
        from pathlib import Path
        if output:
            Path(output).expanduser().write_text(rendered, encoding="utf-8")
            console.print(f"[green]BloodHound ACL analysis written to:[/green] {output}")
        if graph:
            Path(graph).expanduser().write_text(report["mermaid_graph"] + "\n", encoding="utf-8")
            console.print(f"[green]Candidate path graph written to:[/green] {graph}")
        console.print_json(rendered)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]BloodHound analysis failed:[/red] {exc}")
        raise typer.Exit(2)


@app.command()
def acl(
    target: str = typer.Option(..., "--target", help="Target object's sAMAccountName."),
    principal: str = typer.Option(..., "--principal", help="Principal to check against the target DACL."),
    config: str = _COMMON["config"],
    server: str = _COMMON["server"],
    port: int = _COMMON["port"],
    use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"],
    username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"],
    verbose: bool = _COMMON["verbose"],
    output: str | None = typer.Option(None, "--output", "-o", help="Optional JSON output path."),
):
    """Read a target DACL and identify allow ACEs for a principal."""
    configure_logging(verbose)
    try:
        settings = _settings(
            config, server, port, use_ssl, base_dn, username, validate_tls
        )
        password = obtain_password()
        with LDAPDirectoryClient(settings, password) as client:
            report = audit_target_acl(
                client,
                settings.base_dn,
                target,
                principal,
            )
        rendered = json.dumps(report, indent=2)
        if output:
            from pathlib import Path
            Path(output).expanduser().write_text(rendered, encoding="utf-8")
            console.print(f"[green]ACL report written to:[/green] {output}")
        console.print_json(rendered)
    except ConfigurationError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2)
    except DirectoryConnectionError as exc:
        err_console.print(f"[red]Connection error:[/red] {exc}")
        raise typer.Exit(3)
    except DirectorySearchError as exc:
        err_console.print(f"[red]ACL analysis failed:[/red] {exc}")
        raise typer.Exit(4)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(130)


@app.command("exploit")
def exploit(
    config: str = _COMMON["config"],
    server: str = _COMMON["server"],
    port: int = _COMMON["port"],
    use_ssl: bool = _COMMON["use_ssl"],
    base_dn: str = _COMMON["base_dn"],
    username: str = _COMMON["username"],
    validate_tls: bool = _COMMON["validate_tls"],
    verbose: bool = _COMMON["verbose"],
    acl_password: str = typer.Option(
        None,
        "--acl-password",
        help="Password for the GenericWrite principal (or set DELEGATIONFLOW_PASSWORD).",
    ),
    target_account: str = typer.Option(
        ...,
        "--target-account",
        help="Unconstrained-delegation account to modify (for example callum.dixon).",
    ),
    target_password: str = typer.Option(
        None,
        "--target-password",
        help="Password of the unconstrained-delegation account.",
    ),
    target_hash: str = typer.Option(
        None,
        "--target-hash",
        help="NT hash of the unconstrained-delegation account (32 hex characters).",
    ),
    target_aes_key: str = typer.Option(
        None,
        "--target-aes-key",
        help="Optional AES key for the delegation account if RC4 is disabled.",
    ),
    attacker_host: str = typer.Option(
        "roguecomputer",
        "--attacker-host",
        help="DNS name the target will authenticate to (default: roguecomputer).",
    ),
    attacker_ip: str = typer.Option(
        None,
        "--attacker-ip",
        help="IP the target should reach for SMB 445 (default: auto-detect).",
    ),
    dc_host: str = typer.Option(
        None,
        "--dc-host",
        help="DC DNS hostname used for the Kerberos SPN (default: auto-discover).",
    ),
    coerce_target: str = typer.Option(
        None,
        "--coerce-target",
        help="Host to coerce (default: the --server value).",
    ),
    loot_dir: str = typer.Option(
        "delegationflow-loot",
        "--loot-dir",
        help="Directory for captured ticket caches.",
    ),
    flag_path: str = typer.Option(
        r"C:\flag.txt",
        "--flag-path",
        help="Remote file to read after DCSync.",
    ),
    timeout: float = typer.Option(
        60.0,
        "--timeout",
        help="Seconds to wait for the coerced authentication.",
    ),
    cleanup: bool = typer.Option(
        False,
        "--cleanup",
        help="Remove the SPN and DNS record created by this run.",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional JSON result path.",
    ),
):
    """Run the authorized GenericWrite → unconstrained delegation → DCSync chain.

    This command performs write operations and is intentionally separate from the
    read-only assessment commands.  Use it only against systems you are authorized
    to test.
    """
    configure_logging(verbose)
    try:
        settings = _settings(
            config, server, port, use_ssl, base_dn, username, validate_tls
        )
        acl_secret = acl_password or obtain_password()
        if not target_password and not target_hash:
            target_password = typer.prompt(
                f"Password for {target_account}", hide_input=True
            )

        from delegationflow.exploit.chain import ExploitError, run_chain

        result = run_chain(
            server=settings.server,
            base_dn=settings.base_dn,
            domain=None,
            acl_username=settings.username,
            acl_password=acl_secret,
            target_account=target_account,
            target_password=target_password,
            target_hash=target_hash,
            target_aes_key=target_aes_key,
            attacker_host=attacker_host,
            attacker_ip=attacker_ip,
            dc_host=dc_host,
            coerce_target=coerce_target,
            loot_dir=loot_dir,
            flag_path=flag_path,
            timeout=timeout,
            cleanup=cleanup,
            ldap_port=settings.port,
            ldap_use_ssl=settings.use_ssl,
            status=lambda message: console.print(message),
        )
        rendered = json.dumps(result.as_dict(), indent=2)
        if output:
            from pathlib import Path

            Path(output).expanduser().write_text(rendered, encoding="utf-8")
            console.print(f"[green]Exploit result written to:[/green] {output}")
        console.print_json(rendered)
    except ConfigurationError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2)
    except Exception as exc:
        # ImportError for missing optional extras is also handled here so the
        # read-only commands continue to work without impacket installed.
        err_console.print(f"[red]Exploit failed:[/red] {exc}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(130)


@app.command()
def version():
    """Show the installed DelegationFlow version."""
    console.print(f"DelegationFlow {__version__}")


if __name__ == "__main__":
    app()

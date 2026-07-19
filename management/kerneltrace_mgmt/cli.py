"""Entry point della CLI `kerneltrace-mgmt`, basata su `click`."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from kerneltrace_mgmt import __version__
from kerneltrace_mgmt.client import EventStreamError, filter_by_tag, read_all_events, tail_events
from kerneltrace_mgmt.config_validator import validate_config_file
from kerneltrace_mgmt.rules_manager import validate_rules_directory

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


@click.group()
@click.version_option(version=__version__, prog_name="kerneltrace-mgmt")
def main() -> None:
    """KernelTrace management CLI: rule validation, config validation, and
    event stream inspection, usable without a Rust toolchain installed."""


@main.command()
@click.argument("event_file", type=click.Path(exists=False, path_type=Path))
@click.option("--tag", default=None, help="Show only events carrying this tag.")
def tail(event_file: Path, tag: str | None) -> None:
    """Follow a JSON Lines event file in real time (like 'tail -f')."""
    try:
        stream = tail_events(event_file)
    except EventStreamError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    console.print(f"[dim]Following {event_file} — press Ctrl+C to stop[/dim]")
    try:
        for event in stream:
            tags = event.get("tags", [])
            if tag is not None and tag not in tags:
                continue

            process = event.get("process", {})
            line = (
                f"{event.get('timestamp', '?')} "
                f"[bold]{event.get('event_kind', '?')}[/bold] "
                f"pid={process.get('pid', '?')} comm={process.get('comm', '?')}"
            )
            if tags:
                line += f" [dim]tags=[/dim]{', '.join(tags)}"
            console.print(line)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@main.command(name="grep")
@click.argument("event_file", type=click.Path(exists=True, path_type=Path))
@click.option("--tag", required=True, help="Show only archived events carrying this tag.")
def grep_events(event_file: Path, tag: str) -> None:
    """Search an archived JSON Lines event file for a given tag."""
    try:
        events = read_all_events(event_file)
    except EventStreamError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    matches = filter_by_tag(events, tag)
    console.print(f"Found {len(matches)} event(s) tagged '{tag}' out of {len(events)} total.")

    for event in matches:
        process = event.get("process", {})
        console.print(
            f"{event.get('timestamp', '?')} pid={process.get('pid', '?')} comm={process.get('comm', '?')}"
        )


@main.group()
def rules() -> None:
    """Validate and inspect detection rules."""


@rules.command(name="validate")
@click.argument("directory", type=click.Path(exists=False, path_type=Path))
def rules_validate(directory: Path) -> None:
    """Validate all YAML rule files in DIRECTORY."""
    summaries, errors = validate_rules_directory(directory)

    if errors:
        console.print(f"[bold red]{len(errors)} error(s) found:[/bold red]")
        for error in errors:
            console.print(f"  - {error}")
        console.print(f"\n{len(summaries)} rule(s) valid, {len(errors)} error(s).")
        sys.exit(1)

    console.print(f"[bold green]All {len(summaries)} rule(s) in {directory} are valid.[/bold green]")


@rules.command(name="list")
@click.argument("directory", type=click.Path(exists=False, path_type=Path))
def rules_list(directory: Path) -> None:
    """List all valid YAML rules in DIRECTORY as a table."""
    summaries, errors = validate_rules_directory(directory)

    table = Table(title=f"Detection rules in {directory}")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Kind")
    table.add_column("Enabled")

    for summary in summaries:
        severity_style = SEVERITY_COLORS.get(summary.severity, "white")
        table.add_row(
            summary.id,
            summary.name,
            f"[{severity_style}]{summary.severity}[/{severity_style}]",
            summary.match_kind,
            "yes" if summary.enabled else "no",
        )

    console.print(table)

    if errors:
        console.print(f"\n[bold yellow]{len(errors)} file(s) failed validation and were skipped:[/bold yellow]")
        for error in errors:
            console.print(f"  - {error}")


@main.group()
def config() -> None:
    """Validate agent configuration files."""


@config.command(name="validate")
@click.argument("config_file", type=click.Path(exists=False, path_type=Path))
def config_validate(config_file: Path) -> None:
    """Validate the structure of CONFIG_FILE (kerneltrace.yaml)."""
    result = validate_config_file(config_file)

    if not result.is_valid:
        console.print(f"[bold red]{len(result.issues)} issue(s) found in {config_file}:[/bold red]")
        for issue in result.issues:
            console.print(f"  - {issue}")
        sys.exit(1)

    console.print(f"[bold green]Configuration at {config_file} looks structurally valid.[/bold green]")
    console.print(
        "[dim]Note: this is a lightweight structural check; the authoritative validation "
        "is performed by kerneltrace-agent/kerneltrace-cli at load time.[/dim]"
    )


if __name__ == "__main__":
    main()
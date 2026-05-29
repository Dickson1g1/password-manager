import sys
from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich.text    import Text
from rich         import box
from rich.prompt  import Prompt

# stdout for normal output, stderr for errors — allows piping passwords cleanly
console = Console()
err     = Console(stderr=True)


def prompt_password(label: str = "Master password") -> str:
    """Prompt for a password without echoing it to the terminal."""
    return Prompt.ask(f"[dim]{label}[/dim]", password=True, console=console)


def print_entry(service: str, entry: dict) -> None:
    """Display a single vault entry in a rich panel."""
    import datetime
    created = datetime.datetime.fromtimestamp(entry.get("created_at", 0))

    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("key",   style="dim",  no_wrap=True)
    t.add_column("value", style="bold")

    t.add_row("username", entry.get("username", ""))
    t.add_row("password", entry.get("password", ""))  # shown — user explicitly asked for it
    if entry.get("notes"):
        t.add_row("notes", entry["notes"])
    t.add_row("created", created.strftime("%Y-%m-%d %H:%M"))

    console.print(Panel(t, title=f"[bold]{service}[/bold]", border_style="dim"))


def print_entry_list(services: list[str]) -> None:
    """Print a table of all service names."""
    if not services:
        console.print("[dim]No entries in vault.[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("#",       style="dim", width=4)
    t.add_column("Service", style="bold")

    for i, svc in enumerate(services, 1):
        t.add_row(str(i), svc)

    console.print(t)


def print_success(msg: str) -> None:
    console.print(f"[bold green]✔[/bold green]  {msg}")


def print_error(msg: str) -> None:
    """Errors go to stderr so they don't pollute piped output."""
    err.print(f"[bold red]✘[/bold red]  {msg}")

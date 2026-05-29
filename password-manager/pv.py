#!/usr/bin/env python3
"""pv — encrypted local password vault."""

import argparse
import sys

from vault.manager    import (init_vault, add_entry, get_entry,
                               list_entries, delete_entry, rotate_master_password)
from vault.generator  import generate
from vault.display    import (prompt_password, print_entry, print_entry_list,
                               print_success, print_error, console)
from vault.exceptions import (VaultError, WrongPasswordError,
                               EntryExistsError, EntryNotFoundError)


def cmd_init(args) -> int:
    pw = prompt_password("Choose a master password")
    confirm = prompt_password("Confirm master password")
    if pw != confirm:
        print_error("Passwords do not match")
        return 1
    init_vault(pw)
    print_success("Vault created at ~/.password-vault/vault.json")
    return 0


def cmd_add(args) -> int:
    pw       = prompt_password()
    username = args.username or console.input("[dim]Username:[/dim] ")
    # Use generator if --generate flag set, otherwise prompt
    if args.generate:
        password = generate(length=args.length)
        console.print(f"[dim]Generated password:[/dim] [bold]{password}[/bold]")
    else:
        password = prompt_password("Password for this entry")
    notes = args.notes or ""
    add_entry(pw, args.service, username, password, notes, force=args.force)
    print_success(f"Added '{args.service}'")
    return 0


def cmd_get(args) -> int:
    pw    = prompt_password()
    entry = get_entry(pw, args.service)
    if args.password_only:
        # Print ONLY the password to stdout — clean for shell piping:
        # pv get github --password-only | xclip -selection clipboard
        print(entry["password"])
    else:
        print_entry(args.service, entry)
    return 0


def cmd_list(args) -> int:
    pw       = prompt_password()
    services = list_entries(pw)
    print_entry_list(services)
    return 0


def cmd_delete(args) -> int:
    pw = prompt_password()
    # Require explicit confirmation — deletion is irreversible
    confirm = console.input(f"[yellow]Delete '{args.service}'? [y/N]:[/yellow] ")
    if confirm.strip().lower() != "y":
        console.print("[dim]Aborted.[/dim]")
        return 0
    delete_entry(pw, args.service)
    print_success(f"Deleted '{args.service}'")
    return 0


def cmd_rotate(args) -> int:
    old_pw  = prompt_password("Current master password")
    new_pw  = prompt_password("New master password")
    confirm = prompt_password("Confirm new master password")
    if new_pw != confirm:
        print_error("New passwords do not match")
        return 1
    rotate_master_password(old_pw, new_pw)
    print_success("Master password rotated — vault re-encrypted with fresh salt")
    return 0


def cmd_generate(args) -> int:
    """Standalone password generator — no vault interaction required."""
    pw = generate(
        length=args.length,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
    )
    print(pw)   # bare print — easy to pipe to clipboard
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pv", description="Encrypted local password vault")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Create a new vault")

    a = sub.add_parser("add", help="Add a new entry")
    a.add_argument("service")
    a.add_argument("-u", "--username", default="")
    a.add_argument("-n", "--notes",    default="")
    a.add_argument("-g", "--generate", action="store_true", help="Generate password")
    a.add_argument("-l", "--length",   type=int, default=20)
    a.add_argument("--force",          action="store_true", help="Overwrite if exists")

    g = sub.add_parser("get", help="Retrieve an entry")
    g.add_argument("service")
    g.add_argument("-p", "--password-only", action="store_true",
                   help="Print only the password (for piping)")

    sub.add_parser("list", help="List all services")

    d = sub.add_parser("delete", help="Delete an entry")
    d.add_argument("service")

    sub.add_parser("rotate", help="Change master password")

    gen = sub.add_parser("generate", help="Generate a password without storing it")
    gen.add_argument("-l", "--length",     type=int,  default=20)
    gen.add_argument("--no-upper",         action="store_true")
    gen.add_argument("--no-digits",        action="store_true")
    gen.add_argument("--no-symbols",       action="store_true")

    return p


COMMANDS = {
    "init":     cmd_init,
    "add":      cmd_add,
    "get":      cmd_get,
    "list":     cmd_list,
    "delete":   cmd_delete,
    "rotate":   cmd_rotate,
    "generate": cmd_generate,
}


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    handler = COMMANDS[args.cmd]

    try:
        sys.exit(handler(args))
    except WrongPasswordError as e:
        print_error(str(e))
        sys.exit(2)
    except VaultError as e:
        print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")
        sys.exit(130)   # standard exit code for Ctrl-C


if __name__ == "__main__":
    main()

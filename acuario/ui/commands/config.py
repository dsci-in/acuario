"""Config subcommand."""

from rich.text import Text

from acuario.ui import theme


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "config",
        help="Show or edit configuration (including LLM provider setup)",
    )
    parser.add_argument(
        "--set", nargs=2, metavar=("KEY", "VALUE"), help="Set a configuration value"
    )
    parser.add_argument("--save", help="Save configuration to file")
    parser.add_argument(
        "--set-provider",
        nargs="*",
        metavar="KEY=VALUE",
        help=(
            "Configure the default LLM endpoint and persist to "
            "~/.acuario/config.yaml. Accepts: base_url=..., "
            "api_key=..., model=..., auth=... "
            "Example: acuario config --set-provider "
            "base_url=https://openrouter.ai/api/v1 "
            "api_key='${OPENROUTER_API_KEY}' "
            "model=anthropic/claude-opus-4"
        ),
    )
    parser.add_argument(
        "--show-provider",
        action="store_true",
        help="Print the current LLM provider configuration (CLI + env + config.yaml merged)",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help=(
            "Show secret values (api_key / *password / *token / *secret) in "
            "cleartext instead of redacting them"
        ),
    )
    return parser


def handle(cli, args):
    """Show or edit configuration."""
    if args.set:
        key, value = args.set
        keys = key.split(".")
        cli.config.set(*keys, value=value)
        # theme.success escapes its text, so a `[` in a user-supplied key/value
        # renders verbatim instead of crashing the markup parser.
        cli.console.print(theme.success(f"Set {key} = {value}"))

    if args.set_provider is not None:
        _apply_set_provider(cli, args.set_provider)
        return

    if args.show_provider:
        _show_provider(cli)
        return

    if args.save:
        cli.config.save(args.save)
        cli.console.print(theme.success(f"Configuration saved to {args.save}"))

    _show_config(cli, show_secrets=args.show_secrets)


_SECRET_HINTS = ("api_key", "password", "token", "secret")


def _is_secret_key(key) -> bool:
    k = str(key).lower()
    return any(hint in k for hint in _SECRET_HINTS)


def _render_value(key, value, *, show_secrets: bool) -> Text:
    """A themed cell for one config value: secrets redacted (unless opted in),
    long numeric lists collapsed, everything else escaped via Text (never markup)."""
    if _is_secret_key(key) and not show_secrets:
        is_set = bool(value) and str(value) not in ("", "not-needed")
        return Text("••• set" if is_set else "(unset)", style="warn" if is_set else "muted")
    if isinstance(value, bool):  # before any int/list check (bool is an int subclass)
        return Text("yes" if value else "no")
    if isinstance(value, (list, tuple)) and len(value) > 8:
        return Text(f"{value[0]}…{value[-1]}  ({len(value)} values)", style="muted")
    return Text(str(value))


def _show_config(cli, *, show_secrets: bool = False) -> None:
    """Render the merged config as grouped key/value tables instead of a raw
    ``str(dict)`` dump: collapses the ~1024-port lists, drops Python-repr syntax,
    and redacts secret-ish keys (``--show-secrets`` opts back in)."""
    from rich.console import Group

    blocks: list = []
    for section, body in cli.config.config.items():
        blocks.append(theme.section_rule(str(section)))
        if isinstance(body, dict):
            rows = [(k, _render_value(k, v, show_secrets=show_secrets)) for k, v in body.items()]
        else:
            rows = [(section, _render_value(section, body, show_secrets=show_secrets))]
        blocks.append(theme.kv_table(rows))
    cli.console.print(theme.panel(Group(*blocks), title="Current configuration", kind="info"))


def _apply_set_provider(cli, pairs: list[str]) -> None:
    """Persist a `provider:` section to ~/.acuario/config.yaml.

    Merges with any existing config file - leaves unrelated sections
    (scanning, exploitation, reporting, database) untouched.
    """
    if not pairs:
        cli.console.print(
            theme.error(
                "--set-provider requires KEY=VALUE pairs. Example: --set-provider "
                "base_url=https://openrouter.ai/api/v1 "
                "api_key='${OPENROUTER_API_KEY}' model=anthropic/claude-opus-4"
            )
        )
        return

    updates: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            cli.console.print(
                theme.error(
                    f"{pair!r} is not a KEY=VALUE pair. "
                    "Expected base_url=... / api_key=... / model=... / auth=..."
                )
            )
            return
        key, value = pair.split("=", 1)
        key = key.strip().lower()
        if key not in ("base_url", "api_key", "model", "auth"):
            cli.console.print(
                theme.error(
                    f"unknown provider key {key!r}. "
                    "Expected one of: base_url, api_key, model, auth."
                )
            )
            return
        updates[key] = value.strip()

    # Merge into the existing provider: section (preserves fields the
    # user didn't override this time).
    current = cli.config.get_provider_section()
    current.update(updates)
    cli.config.set("provider", value=current)

    # Persist to ~/.acuario/config.yaml, preserving any other sections
    # in the file. We avoid `cli.config.save()` because that would dump
    # the full merged default config (including the 1024-port scanning
    # defaults) - ballooning the file for a 3-key write.
    import yaml

    path = cli.config.DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text()) or {}
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            existing = {}

    existing["provider"] = current
    path.write_text(yaml.safe_dump(existing, default_flow_style=False, sort_keys=True))

    saved = theme.success("Saved provider config to ")
    saved.append(str(path), style="path")
    cli.console.print(saved)
    _show_provider(cli)


def _show_provider(cli) -> None:
    """Print the effective provider triple after CLI/env/config merging."""
    from ...providers import resolve_llm_endpoint

    # No CLI flags on `config` - show env + config.yaml state.
    endpoint = resolve_llm_endpoint(
        config_provider=cli.config.get_provider_section(),
    )

    # Body as a Text (styled appends), so an endpoint value with a bracket is
    # rendered verbatim rather than parsed as markup.
    body = Text()
    key_set = endpoint.api_key
    for i, (label, value, style) in enumerate((
        ("provider", str(endpoint.provider), "accent"),
        ("model", str(endpoint.model), "accent"),
        ("base_url", str(endpoint.base_url or "(Anthropic direct)"), "path"),
        ("api_key", "(set)" if key_set else "(NOT SET)", "success" if key_set else "warn"),
        ("source", str(endpoint.source), "muted"),
    )):
        if i:
            body.append("\n")
        body.append(f"  {label:<9} ", style="muted")
        body.append(value, style=style)
    cli.console.print(theme.panel(body, title="LLM provider", kind="accent"))

    # Helpful next-step hints
    file_path = cli.config.DEFAULT_CONFIG_PATH
    if endpoint.source == "default" and not file_path.exists():
        cli.console.print(theme.warn("No provider configured. Options:"))
        for hint in (
            "1. Set ANTHROPIC_API_KEY for Anthropic direct",
            "2. Set ACUARIO_BASE_URL + ACUARIO_API_KEY for an OpenAI-compatible endpoint",
            "3. Run `acuario config --set-provider base_url=... api_key=... model=...`",
            "4. See `docs/providers.md` for OpenRouter / Ollama / LM Studio / vLLM snippets",
        ):
            cli.console.print(theme.muted(f"  {hint}"))

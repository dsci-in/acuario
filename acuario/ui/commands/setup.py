"""Interactive provider-configuration wizard.

`acuario setup` walks a first-time user through picking an LLM
backend, entering credentials, and persisting the result to
`~/.acuario/config.yaml`. Every step validates before moving on
(API key shape, base_url reachability, optional test invoke) so a
misconfigured file doesn't silently make the rest of Acuario
unusable.

The wizard is a thin shell over the primitives the `config
--set-provider` subcommand already ships; its value is the
decision tree, not new file handling.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.text import Text

from acuario import __version__
from acuario.ui import theme

if TYPE_CHECKING:
    from acuario.providers import ProviderPreset


#: Subcommand aliases recognized by the CLI dispatcher.
ALIASES: tuple[str, ...] = ("init",)


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "setup",
        aliases=["init"],
        help="Interactive wizard to configure your LLM provider",
        description=(
            "Walk through provider selection, credential entry, optional connection\n"
            "testing, and persistence to ~/.acuario/config.yaml. Safe to re-run -\n"
            "existing config is shown and can be overwritten."
        ),
    )
    parser.add_argument(
        "--provider",
        metavar="KEY",
        help=(
            "Skip the menu and configure this provider directly "
            "(e.g. openrouter, ollama, lmstudio, anthropic, openai, "
            "openai-oauth, together, groq, deepseek, fireworks, custom)"
        ),
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="For OAuth providers, don't open the browser automatically",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="For OAuth providers, local callback wait timeout",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Don't test the endpoint after writing config (default: test)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Assume 'yes' on overwrite confirmations (non-interactive mode)",
    )
    return parser


def handle(cli, args) -> None:
    """Run the setup wizard."""
    from acuario.providers import KNOWN_PROVIDERS, preset_by_key

    console: Console = cli.console

    _print_welcome(console, cli)

    console.print(theme.section_rule("Step 1 · provider"))

    # Direct mode - user knows exactly which provider they want
    if args.provider:
        preset = preset_by_key(args.provider)
        if preset is None:
            known = ", ".join(p.key for p in KNOWN_PROVIDERS)
            # theme.error escapes its text, so a bracket in the user-typed
            # provider name renders verbatim instead of crashing the markup parser.
            console.print(theme.error(f"Unknown provider {args.provider!r}. Known keys: {known}"))
            return
    else:
        preset = _prompt_provider_choice(console, KNOWN_PROVIDERS)
        if preset is None:
            console.print(theme.warn("Setup cancelled."))
            return

    console.print()
    console.print(theme.accent(f"Configuring {preset.display_name}"))
    console.print(theme.muted(f"Docs: {preset.docs_url}"))
    console.print()

    # Per-provider inputs
    console.print(theme.section_rule("Step 2 · credentials"))
    base_url = _prompt_base_url(console, preset)
    if base_url == "":
        base_url = None  # Anthropic direct has no base_url
    api_key_literal = _prompt_api_key(
        console,
        preset,
        no_open=bool(getattr(args, "no_open", False)),
        timeout_seconds=int(getattr(args, "timeout_seconds", 60)),
    )
    model = _prompt_model(
        console,
        preset,
        base_url=base_url,
        api_key_literal=api_key_literal,
    )

    if model == "" and preset.key != "anthropic":
        console.print(theme.error("model cannot be empty for OpenAI-compat endpoints."))
        return

    # Confirm + write
    _print_config_preview(console, preset, base_url, api_key_literal, model)
    if not args.yes:
        existing = cli.config.get_provider_section()
        if existing:
            console.print()
            console.print(
                theme.warn(f"An existing provider config was found in {cli.config.DEFAULT_CONFIG_PATH}")
            )
            if not Confirm.ask("Overwrite it?", default=True, console=console):
                console.print(theme.warn("Setup cancelled."))
                return
        elif not Confirm.ask(f"\nWrite this to {cli.config.DEFAULT_CONFIG_PATH}?", default=True, console=console):
            console.print(theme.warn("Setup cancelled."))
            return

    # Persist
    _write_config(cli, preset, base_url, api_key_literal, model)

    # Test invoke (unless --no-test)
    if not args.no_test:
        _run_test_invoke(console, preset, base_url, api_key_literal, model)

    # Final status
    console.print()
    console.print(theme.success("Setup complete."))

    # "Next steps" send-off: a Text body (styled appends, never markup), so the
    # command names carry the accent tone while staying injection-safe, wrapped
    # in an accent-framed panel that closes the wizard.
    steps = Text()
    steps.append("Run ")
    steps.append("acuario config --show-provider", style="accent")
    steps.append(" anytime to inspect your saved endpoint.\n")
    steps.append("Run ")
    steps.append("acuario doctor", style="accent")
    steps.append(" to validate your full environment.\n")
    steps.append("Run ")
    steps.append("acuario audit .", style="accent")
    steps.append(" to start your first scan.")
    console.print()
    console.print(theme.panel(steps, title="Next steps", kind="accent"))


# --- UI helpers -----------------------------------------------------------


def _print_welcome(console: Console, cli) -> None:
    from acuario.ui.cli import BANNER

    console.print(theme.brand_banner(BANNER, console=console))
    existing = cli.config.get_provider_section()
    # Build the body as a Text (styles applied directly), so a bracket in the
    # config path or a saved model/base_url renders verbatim.
    body = Text()
    body.append(f"Acuario {__version__} · LLM provider setup", style="title")
    body.append("\n\nThis wizard configures an LLM backend for Acuario's source-code\n")
    body.append("analysis pipelines. Your selection persists to\n  ")
    body.append(str(cli.config.DEFAULT_CONFIG_PATH), style="path")
    if existing:
        base_url = existing.get("base_url") or "(Anthropic direct)"
        model = existing.get("model") or "(default)"
        body.append("\n\n")
        body.append("Current config", style="muted")
        body.append("\n  model:    ")
        body.append(str(model), style="accent")
        body.append("\n  base_url: ")
        body.append(str(base_url), style="path")
    console.print(theme.panel(body, kind="accent"))
    console.print()


def _prompt_provider_choice(
    console: Console, presets: tuple[ProviderPreset, ...]
) -> ProviderPreset | None:
    """Menu-driven provider selection."""
    table = theme.framed_table(
        ["#", "NAME", "DESCRIPTION"],
        title="Choose a provider",
        caption=f"{len(presets)} provider(s)",
        kind="info",
    )
    table.columns[0].justify = "right"
    table.columns[0].style = "faint"
    table.columns[1].style = "ident"
    for i, preset in enumerate(presets, start=1):
        table.add_row(theme.field(str(i)), theme.field(preset.display_name), theme.field(preset.description))
    table.add_row(theme.field("0"), theme.muted("Cancel"), theme.field(""))

    console.print(table)
    choice = IntPrompt.ask(
        "\nSelection",
        default=1,
        choices=[str(i) for i in range(0, len(presets) + 1)],
        show_choices=False,
        console=console,
    )
    if choice == 0:
        return None
    return presets[choice - 1]


def _prompt_base_url(console: Console, preset: ProviderPreset) -> str:
    """Prompt for base_url with a provider-appropriate default."""
    if preset.auth_flow == "openai_codex":
        console.print(
            theme.muted("OpenAI OAuth uses the ChatGPT Codex backend (no Platform API key or /v1 base URL).")
        )
        return preset.default_base_url or "https://chatgpt.com/backend-api"

    if preset.default_base_url is None:
        # Anthropic direct - no base_url to configure
        console.print(theme.muted("Anthropic direct uses api.anthropic.com (no base URL to set)."))
        return ""

    default = preset.default_base_url
    return Prompt.ask(
        "Base URL",
        default=default,
        console=console,
    ).strip()


def _prompt_api_key(
    console: Console,
    preset: ProviderPreset,
    *,
    no_open: bool = False,
    timeout_seconds: int = 60,
) -> str:
    """Prompt for the API key literal to store in config.yaml.

    Three behaviors depending on provider:

    - Keyless backends (Ollama, LM Studio): skip the prompt entirely
      and store `"ollama"` / `"not-needed"` as a placeholder.
    - Keyed backend with a known env var that's set in the current
      shell: offer to store `${NAME}` as a literal instead of the
      actual secret, so the YAML file never contains credentials.
    - Otherwise: prompt for the literal secret (Rich's Prompt masks
      it by default).
    """
    if preset.auth_flow == "openai_codex":
        from acuario.providers.openai_oauth import (
            ensure_fresh_openai_oauth_credentials,
            load_openai_oauth_credentials,
            login_openai_oauth,
        )

        existing = load_openai_oauth_credentials()
        if existing:
            try:
                creds = ensure_fresh_openai_oauth_credentials()
                console.print(
                    theme.muted(f"Using stored OpenAI OAuth credentials for account_id={creds.account_id}.")
                )
                return ""
            except Exception as exc:
                console.print(theme.warn(f"Stored OpenAI OAuth credentials need renewal: {exc}"))

        console.print(
            theme.muted("Starting OpenAI browser OAuth. Credentials are stored under ~/.acuario/auth/.")
        )
        creds = login_openai_oauth(
            no_open=no_open,
            timeout_seconds=timeout_seconds,
            print_fn=console.print,
        )
        done = theme.success("OpenAI OAuth login complete.")
        done.append(f" account_id={creds.account_id}", style="muted")
        console.print(done)
        return ""

    if preset.is_local and preset.api_key_env_var is None:
        placeholder = "ollama" if "11434" in (preset.default_base_url or "") else "not-needed"
        console.print(
            theme.muted(f"{preset.display_name} is keyless, storing {placeholder!r} as a placeholder.")
        )
        return placeholder

    env_var = preset.api_key_env_var
    env_value = os.environ.get(env_var) if env_var else None

    if env_var and env_value:
        console.print(theme.muted(f"Detected ${env_var} in your environment (length {len(env_value)})."))
        use_env = Confirm.ask(
            f"Store as [bold]${{{env_var}}}[/bold] (keeps the secret out of the file)?",
            default=True,
            console=console,
        )
        if use_env:
            return f"${{{env_var}}}"

    if env_var:
        console.print(
            theme.muted(f"Get an API key at {preset.docs_url} (or set ${env_var} and re-run setup).")
        )
    else:
        console.print(theme.muted(f"Get an API key at {preset.docs_url}."))

    api_key = Prompt.ask("API key", password=True, default="", console=console).strip()
    return api_key


def _fetch_ollama_models(base_url: str) -> list[str]:
    """Fetch the list of pulled models from a live Ollama endpoint.

    Calls ``GET <base_url>/api/tags`` and returns a sorted list of
    model name strings. Returns an empty list on any network or parse
    error so callers can fall back gracefully.
    """
    import json
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        return sorted(m["name"] for m in data.get("models", []) if "name" in m)
    except Exception:
        return []


def _fetch_openai_compat_models(base_url: str, api_key: str = "") -> list[str]:
    """Fetch the model list from any OpenAI-compatible endpoint.

    Hits ``GET <base_url>/models`` (the standard OpenAI catalog endpoint
    that vLLM, SGLang, LM Studio, OpenRouter, OpenAI itself, Together,
    Groq, DeepSeek, Fireworks, etc. all implement). Strips a trailing
    ``/chat/completions`` segment if the user pasted the full chat URL
    by mistake.

    Returns a sorted list of model id strings, or an empty list on any
    network / auth / parse error so callers can fall back to a
    free-text prompt.
    """
    import json
    import urllib.error
    import urllib.request

    # Normalise: tolerate users pasting the full /chat/completions URL.
    base = base_url.rstrip("/")
    for suffix in ("/chat/completions", "/responses"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    url = base + "/models"

    headers = {"Accept": "application/json"}
    if api_key and not (api_key.startswith("${") and api_key.endswith("}")):
        # Don't send unresolved ${ENV_VAR} placeholders as bearer tokens.
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for entry in items:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            out.append(entry["id"])
    return sorted(out)


def _select_from_live_models(console: Console, models: list[str], source_label: str) -> str | None:
    """Render the numbered model menu and return the selected id.

    Returns ``None`` if the user picked "type a custom name instead"
    so the caller can fall through to the free-text prompt.
    """
    # Source label is a free-text base_url, so it goes in a themed rule (escaped)
    # rather than a markup-parsed table title.
    console.print(theme.section_rule(f"models at {source_label}"))
    table = theme.framed_table(
        ["#", "MODEL NAME"],
        title="Available models",
        caption=f"{len(models)} model(s)",
        kind="info",
    )
    table.columns[0].justify = "right"
    table.columns[0].style = "faint"
    table.columns[1].style = "ident"
    for i, name in enumerate(models, start=1):
        table.add_row(theme.field(str(i)), theme.field(name))
    table.add_row(theme.field("0"), theme.muted("Type a custom name instead"))
    console.print(table)

    choice = IntPrompt.ask(
        "Select a model",
        default=1,
        choices=[str(i) for i in range(0, len(models) + 1)],
        show_choices=False,
        console=console,
    )
    if choice == 0:
        return None
    return models[choice - 1]


def _prompt_model(
    console: Console,
    preset: ProviderPreset,
    base_url: str | None = None,
    api_key_literal: str | None = None,
) -> str:
    """Prompt for the default model identifier.

    Tries to fetch the live model list from the provider before falling
    back to a typed prompt:
      - Ollama → ``GET /api/tags``
      - Any OpenAI-compat endpoint (vLLM, SGLang, LM Studio, OpenAI,
        OpenRouter, Together, Groq, DeepSeek, Fireworks, MiniMax,
        custom) → ``GET /models``

    The free-text fallback runs whenever the live fetch returns no
    models, the network is unreachable, or the user explicitly picks
    "Type a custom name instead" from the menu.
    """
    # --- Ollama: native /api/tags ---------------------------------------
    if preset.key == "ollama" and base_url:
        console.print()
        console.print(theme.muted("Fetching available models from Ollama endpoint…"))
        live_models = _fetch_ollama_models(base_url)
        if live_models:
            picked = _select_from_live_models(console, live_models, base_url)
            if picked is not None:
                return picked
        else:
            console.print(
                theme.warn("Could not reach the Ollama endpoint to fetch models. Enter the model name manually.")
            )

    # --- Any OpenAI-compatible endpoint: /v1/models ---------------------
    elif preset.is_openai_compat and base_url:
        console.print()
        console.print(theme.muted(f"Fetching available models from {preset.display_name} endpoint…"))
        live_models = _fetch_openai_compat_models(base_url, api_key_literal or "")
        if live_models:
            picked = _select_from_live_models(console, live_models, base_url)
            if picked is not None:
                return picked
        else:
            console.print(
                theme.warn(
                    "Could not fetch the model list from the endpoint "
                    "(network error, auth missing, or /models not implemented). "
                    "Enter the model name manually."
                )
            )

    # --- Fallback: show suggestions + free-text prompt ------------------
    if preset.alt_models:
        console.print()
        console.print(theme.muted("Common models for this provider:"))
        console.print(theme.muted(f"  {preset.default_model} (default)"))
        for alt in preset.alt_models:
            console.print(theme.muted(f"  {alt}"))

    return Prompt.ask(
        "\nModel",
        default=preset.default_model,
        console=console,
    ).strip()


def _print_config_preview(
    console: Console,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Show the YAML that's about to be written, masking secrets."""
    masked = _mask_secret(api_key_literal)
    # Body as a Text (styled appends), so a bracket in a user-typed base_url /
    # model / masked key renders verbatim instead of being parsed as markup.
    body = Text("provider:", style="muted")
    if preset.auth_flow:
        body.append("\n  auth:     ")
        body.append(str(preset.auth_flow), style="accent")
    if base_url:
        body.append("\n  base_url: ")
        body.append(str(base_url), style="path")
    if masked:
        body.append("\n  api_key:  ")
        body.append(str(masked), style="muted")
    body.append("\n  model:    ")
    body.append(str(model), style="accent")

    console.print(theme.panel(body, title=f"{preset.display_name} config", kind="success"))


def _mask_secret(value: str) -> str:
    """Hide the middle of a literal secret. `${ENV_VAR}` references
    pass through unchanged because they're not actually secrets."""
    if not value:
        return ""
    if value.startswith("${") and value.endswith("}"):
        return value
    if value in ("ollama", "not-needed", "lm-studio"):
        return value
    if len(value) <= 12:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"


def _write_config(
    cli,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Persist the provider section to ~/.acuario/config.yaml.

    Merges with any existing config file - leaves unrelated sections
    (scanning, exploitation, reporting, database) untouched. We do
    NOT go through `cli.config.save()` because that dumps the entire
    merged default config (including the 1024-port scanning defaults),
    which would balloon the file to ~1000 lines for a 3-key write.
    """
    import yaml

    provider_section: dict[str, str] = {}
    if preset.auth_flow:
        provider_section["auth"] = preset.auth_flow
    if base_url:
        provider_section["base_url"] = base_url
    if api_key_literal:
        provider_section["api_key"] = api_key_literal
    if model:
        provider_section["model"] = model
    if preset.provider_adapter:
        # Presets like `openai-responses` that target a specific
        # genai-pyo3 adapter persist the name so the provider manager
        # doesn't have to guess from the base URL.
        provider_section["adapter"] = preset.provider_adapter

    path = cli.config.DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing file (if any), merge provider:, write back.
    existing: dict = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text()) or {}
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            existing = {}

    existing["provider"] = provider_section
    path.write_text(yaml.safe_dump(existing, default_flow_style=False, sort_keys=True))

    # Keep the in-memory Config object in sync for the current process.
    cli.config.set("provider", value=provider_section)

    cli.console.print()
    wrote = theme.success("Wrote ")
    wrote.append(str(path), style="path")
    cli.console.print(wrote)


def _print_test_failed(console: Console, exc: object) -> None:
    """Report a failed health check. ``exc`` is escaped (theme.error), so an
    exception message containing brackets never crashes the markup parser."""
    console.print()  # break off the inline "Testing endpoint… " line
    console.print(theme.error(f"Test failed: {exc}"))
    console.print(
        theme.warn("The config was still written. Run `acuario doctor` for a fuller diagnosis.")
    )


def _print_test_ok(console: Console, elapsed_ms: int, snippet: str) -> None:
    """Report a passing health check. The LLM reply is appended as styled text
    (not markup), so a bracket in the model's output renders verbatim."""
    line = theme.success("ok")
    line.append(f" ({elapsed_ms}ms, reply: {snippet!r})", style="muted")
    console.print(line)


def _run_test_invoke(
    console: Console,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Best-effort health check: build the LLM and fire one tiny prompt.

    Logs the round-trip time on success, or a helpful error message on
    failure. Never raises - a failed test shouldn't block the user
    from completing setup (their config might be right but the
    service might be temporarily down).
    """
    from acuario.providers import LLMEndpoint, ProviderManager

    if preset.auth_flow == "openai_codex":
        endpoint = LLMEndpoint(
            provider="openai_codex",
            model=model,
            base_url=base_url,
            api_key=None,
            source="cli",
        )
        console.print(theme.muted("Testing endpoint…"), end=" ")
        try:
            llm = ProviderManager.for_endpoint(endpoint).get_llm("default")
            start = time.monotonic()
            response = llm.invoke("Reply with exactly the word PONG.")
            elapsed_ms = int((time.monotonic() - start) * 1000)
        except Exception as exc:
            _print_test_failed(console, exc)
            return

        content = getattr(response, "content", str(response))
        if isinstance(content, list):
            content = " ".join(str(p) for p in content)
        snippet = str(content).strip()[:60]
        _print_test_ok(console, elapsed_ms, snippet)
        return

    # Resolve the literal api_key if the user chose ${ENV_VAR} form
    resolved_key = api_key_literal
    if api_key_literal.startswith("${") and api_key_literal.endswith("}"):
        env_name = api_key_literal[2:-1]
        resolved_key = os.environ.get(env_name, "")
        if not resolved_key:
            console.print(
                theme.warn(
                    f"Skipping test: ${env_name} is not set in this shell. "
                    "Export it and re-run, or use `acuario doctor`."
                )
            )
            return

    if preset.is_openai_compat and base_url:
        endpoint = LLMEndpoint(
            provider="openai_compat",
            model=model,
            base_url=base_url,
            api_key=resolved_key or "not-needed",
            source="cli",
        )
    else:
        # Anthropic direct (base_url=None) or an Anthropic-compatible gateway
        # like MiniMax (base_url set, provider still "anthropic").
        endpoint = LLMEndpoint(
            provider="anthropic",
            model=model,
            base_url=base_url or None,
            api_key=resolved_key or None,
            source="cli",
        )

    console.print(theme.muted("Testing endpoint…"), end=" ")
    try:
        llm = ProviderManager.for_endpoint(endpoint).get_llm("default")
        start = time.monotonic()
        response = llm.invoke("Reply with exactly the word PONG.")
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except Exception as exc:
        _print_test_failed(console, exc)
        return

    content = getattr(response, "content", str(response))
    if isinstance(content, list):
        content = " ".join(str(p) for p in content)
    snippet = str(content).strip()[:60]
    _print_test_ok(console, elapsed_ms, snippet)

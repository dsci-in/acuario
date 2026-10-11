# LLM providers

Acuario runs on `genai-pyo3` (native Rust bindings to `rust-genai`),
which speaks every major provider directly. The wizard
(`acuario setup`) exposes a menu of the known backends, each
carrying an explicit **adapter** name that decides the wire
protocol - `anthropic`, `openai` (chat completions), `openai_resp`
(responses API), `openai_codex` (ChatGPT OAuth), `ollama`, or
`gemini`. There's no heuristic guessing: the preset you pick in
the wizard persists `adapter:` into `~/.acuario/config.yaml`
alongside `base_url`, `api_key`, and `model`.

Backends covered below:

- **Anthropic direct** - Claude via `api.anthropic.com` (`anthropic` adapter).
- **OpenAI (Chat Completions)** - GPT-4o / GPT-4o-mini via
  `/v1/chat/completions` (`openai` adapter).
- **OpenAI (Responses API)** - GPT-5.x / o-series via `/v1/responses`
  (`openai_resp` adapter). Required for GPT-5.x and o-series.
- **OpenAI OAuth (ChatGPT)** - Plus/Pro login via Codex backend (`openai_codex`).
- **OpenRouter, Together, Groq, Fireworks, DeepSeek, LM Studio, vLLM, custom** -
  anything that speaks `/v1/chat/completions` (`openai` adapter).
- **MiniMax** - M2.7 / M2.5 via the Anthropic-compatible endpoint
  (`anthropic` adapter at `api.minimax.io/anthropic`).
- **Ollama** - local models via the native rust-genai Ollama adapter
  (`ollama` adapter at `http://localhost:11434`, no `/v1` suffix).
- **Gemini** - reserved for when a Gemini preset is added; adapter
  name is `gemini`.

This page walks through each backend with copy-paste snippets.

## Fastest path: `acuario setup`

If you just installed Acuario and want to get going, run:

```bash
acuario setup
```

You'll get a menu of every supported provider, prompts for the API
key and model, an optional live-invoke test, and the result written
to `~/.acuario/config.yaml`. The wizard offers to store API keys
as `${ENV_VAR}` references pulled from your shell at runtime, so
you don't have to commit secrets to the file.

Direct variants:

```bash
acuario setup --provider openrouter
acuario setup --provider ollama --no-test
acuario init   # alias
```

Then run `acuario doctor` to validate your environment:

```bash
acuario doctor
```

Doctor probes Python version, credentials, Docker daemon, external
CLI tools (git, ripgrep, gh), optional Python extras, filesystem
permissions, and network reachability to the configured LLM
endpoint - plus an optional live test-invoke with the resolved
model. Green/yellow/red table output with actionable hints on every
warning or error.

## How Acuario picks an LLM

Four sources, highest precedence first:

| # | Source | Fields |
|---|---|---|
| 1 | CLI flags | `--base-url` / `--api-key` / `--model` |
| 2 | Env vars | `ACUARIO_BASE_URL` / `ACUARIO_API_KEY` / `ACUARIO_MODEL` |
| 3 | Config file | `~/.acuario/config.yaml` → `provider:` section |
| 4 | Default | Anthropic via `ANTHROPIC_API_KEY` |

Every command that builds an LLM (`audit`, `setup`, `doctor`,
`report --verify`) threads through the same resolution function, so
setting `ACUARIO_BASE_URL` once covers every code path.

Check the current resolution with:

```bash
acuario config --show-provider
```

which prints the effective model, base URL, API key status, and
source (`cli` / `env` / `config` / `default`).

## Anthropic direct (default)

No setup beyond the API key. This is what Acuario used before
multi-provider support existed and it still works unchanged.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
acuario audit /path/to/repo --model claude-sonnet-4-6
```

Adapter: `anthropic` (the wizard writes this automatically; no
heuristic is involved).

## OpenAI (Chat Completions API)

The classic OpenAI API. Use this for GPT-4o / GPT-4o-mini. For
GPT-5.x and the o-series (o1, o3) use the Responses API preset
below - those models require it.

```bash
acuario setup --provider openai
# or explicitly
export ACUARIO_BASE_URL=https://api.openai.com/v1
export ACUARIO_API_KEY=$OPENAI_API_KEY
export ACUARIO_MODEL=gpt-4o
```

`~/.acuario/config.yaml`:

```yaml
provider:
  base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  model: gpt-4o
  adapter: openai
```

## OpenAI (Responses API)

Required for GPT-5.x and o-series models - those only speak the
newer `/v1/responses` streaming protocol. Works for GPT-4o as well,
but chat-completions is slightly cheaper for older models so pick
the preset that matches your model generation.

```bash
acuario setup --provider openai-responses
# or explicitly
export ACUARIO_BASE_URL=https://api.openai.com/v1
export ACUARIO_API_KEY=$OPENAI_API_KEY
export ACUARIO_MODEL=gpt-5.6-sol
```

`~/.acuario/config.yaml`:

```yaml
provider:
  base_url: https://api.openai.com/v1
  api_key: ${OPENAI_API_KEY}
  model: gpt-5.6-sol
  adapter: openai_resp
```

The `adapter: openai_resp` line is what switches the wire protocol
from chat-completions to responses. Leave it out and the request
will 404 against GPT-5.x models. The wizard writes it automatically
when you pick the `openai-responses` preset.

Any `/v1/responses` proxy works - point `base_url` at your proxy
host, keep `adapter: openai_resp`.

## OpenRouter

OpenRouter routes your request to the specific model you name.
Model names follow the `provider/model` convention:
`anthropic/claude-opus-5`, `openai/gpt-4o`, `meta-llama/llama-3.3-70b-instruct`,
`google/gemini-2.0-flash`, `mistralai/mixtral-8x22b-instruct`, etc.

### Per-command (flags)

```bash
acuario audit /path/to/repo \
    --base-url https://openrouter.ai/api/v1 \
    --api-key "$OPENROUTER_API_KEY" \
    --model anthropic/claude-opus-5
```

### Per-session (env vars)

```bash
export ACUARIO_BASE_URL=https://openrouter.ai/api/v1
export ACUARIO_API_KEY=$OPENROUTER_API_KEY
export ACUARIO_MODEL=anthropic/claude-opus-5

# Every command picks this up automatically
acuario audit /path/to/repo
```

### Persistent (config file)

```bash
acuario config --set-provider \
    base_url=https://openrouter.ai/api/v1 \
    api_key='${OPENROUTER_API_KEY}' \
    model=anthropic/claude-opus-5
```

This writes `~/.acuario/config.yaml` with:

```yaml
provider:
  base_url: https://openrouter.ai/api/v1
  api_key: ${OPENROUTER_API_KEY}
  model: anthropic/claude-opus-5
```

Note that `config --set-provider` writes only `base_url`, `api_key`,
and `model` - it does not persist an `adapter:` line, so the adapter
is inferred from the base URL. To pin an explicit `adapter:` (e.g.
`openai_resp`, `anthropic`), use `acuario setup` or edit the YAML by
hand.

The `${OPENROUTER_API_KEY}` literal is expanded from the environment
at runtime - don't commit real secrets to the YAML. The value
round-trips verbatim, so the shell-quoting you do on the command line
(`'${OPENROUTER_API_KEY}'`) is what preserves the `$`; quote it the
same way if you edit the YAML by hand.

## Ollama

Ollama is spoken natively by `rust-genai` via its own adapter - no
extra install, no `/v1` shim needed. You can also point Acuario at
Ollama's OpenAI-compatible endpoint if you prefer.

### Native Ollama adapter (recommended)

```bash
# Start Ollama
ollama serve &
ollama pull qwen2.5-coder:32b

# Point Acuario at the native Ollama port (no /v1 suffix)
export ACUARIO_BASE_URL=http://localhost:11434
export ACUARIO_MODEL=qwen2.5-coder:32b
# No API key required

acuario audit /path/to/repo --depth standard
```

Or pin it explicitly in `~/.acuario/config.yaml`:

```yaml
provider:
  base_url: http://localhost:11434
  model: qwen2.5-coder:32b
  adapter: ollama
```

### OpenAI-compat endpoint (alternative)

```bash
export ACUARIO_BASE_URL=http://localhost:11434/v1
export ACUARIO_API_KEY=ollama            # placeholder, Ollama ignores it
export ACUARIO_MODEL=qwen2.5-coder:32b
```

**Tool calling caveat**: Acuario requires function calling. Not
every Ollama-served model handles it well. Known-good models as of
2026-04: `qwen2.5-coder:32b`, `qwen2.5:72b`, `llama3.3:70b`,
`mistral-small3:24b`. Base Llama models without function-calling
training will fail on the first tool dispatch.

## LM Studio

LM Studio exposes an OpenAI-compatible endpoint at
`http://localhost:1234/v1` by default. Load a model in the UI, click
"Start Server" in the Developer tab, then:

```bash
export ACUARIO_BASE_URL=http://localhost:1234/v1
export ACUARIO_API_KEY=lm-studio       # placeholder
export ACUARIO_MODEL=local-model       # or the exact LM Studio model name

acuario audit . --depth quick
```

LM Studio's `local-model` placeholder works with whichever model is
currently loaded in the server. If you have multiple models loaded,
pass the exact name from the "Local Server" tab.

## vLLM

```bash
# Start vLLM with an OpenAI-compatible server
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-Coder-32B-Instruct \
    --host 0.0.0.0 --port 8000

# Point Acuario at it
export ACUARIO_BASE_URL=http://localhost:8000/v1
export ACUARIO_API_KEY=vllm
export ACUARIO_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct

acuario audit /path/to/repo
```

### Speed: prefix caching + concurrency

Two server/CLI knobs cut a multi-hour self-hosted audit substantially, with
no change to results.

**1. Prefix caching (`--enable-prefix-caching`).** Launch vLLM with it on:

```bash
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-Coder-32B-Instruct \
    --enable-prefix-caching \
    --host 0.0.0.0 --port 8000
```

vLLM then reuses the KV cache for any request whose token *prefix* it has
already seen, turning repeated prefill into a cache hit. Acuario is built to
exploit this:

- **The analyzer's ReAct loop** re-sends the same system prompt plus the
  growing conversation on every step (up to 500 steps per file). With prefix
  caching on, each step only prefills the *new* turn - steps 2…N reuse all
  prior KV. This is the single biggest win, and it is automatic: the system
  prompt is fixed for the session and the conversation only ever *appends*
  (until a session crosses the ~28k-token trim threshold, where the prefix is
  necessarily rebuilt).
- **The lab agents** (skeptic, critic, orchestrator) and the **prioritizer**
  use byte-identical constant system prompts, so their prefixes are shared
  across *every* call. The skeptic fires once per finding, so this is a large
  number of hits on a busy audit.

> **Measuring hits.** vLLM reports cache hits in its own server logs /
> `/metrics` (`gpu_prefix_cache_hit_rate`). Acuario's native client doesn't
> surface vLLM's `prompt_tokens_details.cached_tokens` today (the genai-pyo3
> `Usage` object only carries prompt/completion/total), so per-call hit
> counts aren't yet in `report.md` - read them from the vLLM side.

> **Cross-file analyzer prefixes.** The analyzer prepends per-file context
> (recalled mechanisms, cross-file callers/callees) at the *top* of its
> system prompt, so its prefix diverges per file - only the within-session
> reuse above applies, not file-to-file. Reordering that front-matter to a
> stable prefix is a known further optimization, deferred until its effect on
> finding quality can be measured.

**2. Request concurrency (`--max-llm-concurrency`).** Acuario defaults to a
conservative in-flight cap (8 general, 4 for the prioritizer, 15 for
`openai_resp`). A multi-GPU
vLLM box can usually sustain far more:

```bash
acuario audit /path/to/repo --max-llm-concurrency 32
# or, equivalently, export ACUARIO_MAX_LLM_CONCURRENCY=32
```

Clamped to 64. Pair it with `--max-parallel` (analyzer fan-out) - the former
caps requests *per* client, the latter caps how many analyzer agents run at
once.

For a **self-tuning** cap instead of a fixed one, set
`ACUARIO_ADAPTIVE_CONCURRENCY=1`: the per-client limit then probes upward on
sustained success and halves on any rate-limit/overload signal (AIMD), between
1 and `max(32, --max-llm-concurrency)`. Off by default - the static cap above
is the proven path; turn this on if your endpoint's spare capacity varies
during a run.

**3. Warm container pool (`--warm-container-pool`).** By default Acuario
cold-spawns a fresh Docker container per analyzed file. On a many-file repo
that `docker run` start cost adds up. The warm pool pre-spawns a small set of
containers once and reuses them:

```bash
acuario audit /path/to/repo --warm-container-pool
```

Each container is reset to a pristine git state between files (`git reset
--hard` + `git clean -fdx` + `/scratch` wipe), and any container that can't be
*verified* clean is dropped and replaced - so reuse never leaks one file's
edits into the next. It's off by default because the per-file-spawn path is the
guaranteed-fresh baseline; turn it on once you've confirmed it on your
workload.

### Behind a reverse proxy (path-routed multi-model gateway)

Some deployments don't expose vLLM by `host:port` directly - instead an
ops team fronts it with an HTTPS gateway that routes to different models
by **URL path**, e.g.:

```
https://llm.example.internal/qwen/v1/chat/completions
https://llm.example.internal/gemma/v1/chat/completions
```

This is the same OpenAI-compatible shape - just with a path prefix
(`/qwen/v1`, `/gemma/v1`) instead of a port. Acuario handles it with no
special configuration: set the **base URL to the full path up to and
including `/v1`**, and the `openai` adapter appends `/chat/completions`
itself. (This is the same mechanism that lets Groq use
`https://api.groq.com/openai/v1` and Fireworks use
`https://api.fireworks.ai/inference/v1`.)

Through the wizard - pick **vLLM (self-hosted)** and answer:

```
Base URL : https://llm.example.internal/qwen/v1
Model    : <auto-fetched from /v1/models, or type it>
API key  : (keyless - any placeholder, e.g. "not-needed")
```

The wizard's model auto-fetch hits `<base_url>/models`, so if the
gateway exposes the standard catalog endpoint you'll get a numbered
pick-list. Otherwise it falls back to a free-text model prompt.

Or non-interactively:

```bash
export ACUARIO_BASE_URL=https://llm.example.internal/qwen/v1
export ACUARIO_API_KEY=not-needed
export ACUARIO_MODEL=qwen3.6-coder        # whatever /v1/models reports
acuario audit /path/to/repo
```

> **DNS note.** If the gateway hostname isn't in public DNS (internal
> appliance), add it to `/etc/hosts` so Acuario - and the sandbox host -
> can resolve it:
> ```
> 10.x.x.x   llm.example.internal
> ```

**Using two path-routed models at once** (e.g. a big coder model for the
analyzer, a faster model for prioritization) is just
[per-task routing](#per-task-routing-advanced) with two different base
URLs - see that section for the `config.yaml` shape.

## Together, Groq, Fireworks, Anyscale, SiliconFlow, DeepSeek

All `/v1/chat/completions` endpoints - same pattern, different base
URL, `adapter: openai`. Together, Groq, Fireworks, and DeepSeek are
dedicated wizard presets; Anyscale and SiliconFlow have no menu entry
of their own and are configured through the generic `custom`
(OpenAI-compatible) preset. The env-var paths are here for scripting.

```bash
# Together
export ACUARIO_BASE_URL=https://api.together.xyz/v1
export ACUARIO_API_KEY=$TOGETHER_API_KEY
export ACUARIO_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo

# Groq
export ACUARIO_BASE_URL=https://api.groq.com/openai/v1
export ACUARIO_API_KEY=$GROQ_API_KEY
export ACUARIO_MODEL=llama-3.3-70b-versatile

# Fireworks
export ACUARIO_BASE_URL=https://api.fireworks.ai/inference/v1
export ACUARIO_API_KEY=$FIREWORKS_API_KEY
export ACUARIO_MODEL=accounts/fireworks/models/qwen2p5-coder-32b-instruct

# DeepSeek
export ACUARIO_BASE_URL=https://api.deepseek.com/v1
export ACUARIO_API_KEY=$DEEPSEEK_API_KEY
export ACUARIO_MODEL=deepseek-chat
```

For OpenAI itself, use the [Chat Completions](#openai-chat-completions-api)
or [Responses](#openai-responses-api) section above - the model
generation decides which.

## MiniMax

MiniMax's M-series reasoning models are served via an
Anthropic-compatible endpoint at `https://api.minimax.io/anthropic`
(not an OpenAI-compat one). The wizard picks the right adapter
automatically.

```bash
acuario setup --provider minimax
# writes adapter: anthropic + base_url: https://api.minimax.io/anthropic
```

`~/.acuario/config.yaml`:

```yaml
provider:
  base_url: https://api.minimax.io/anthropic
  api_key: ${MINIMAX_API_KEY}
  model: MiniMax-M2.7
  adapter: anthropic
```

## Per-task routing (advanced)

For source-hunt runs, Acuario has five distinct tasks:

| Task | What it does | Typical model tier |
|---|---|---|
| `prioritizer` | Scores files by attack surface | Small / fast |
| `analyzer` | Per-file vulnerability discovery (ReAct loop) | Largest available |
| `reviewer` | Adversarial second-pass check | Different tier than analyzer (independence) |
| `exploit_dev` | Exploit triage on crash-reproduced findings | Strongest reasoning |
| `default` | Fallback for anything else | Medium |

By default they all route to the same endpoint. You can override
per-task via `~/.acuario/config.yaml`:

```yaml
providers:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: ${OPENROUTER_API_KEY}
  local_qwen:
    base_url: http://localhost:11434/v1
    api_key: ollama

routes:
  default: openrouter
  prioritizer: openrouter
  analyzer: openrouter
  reviewer: local_qwen              # Independence via cross-provider
  exploit_dev: openrouter

task_models:
  prioritizer: anthropic/claude-haiku-4-5
  analyzer: anthropic/claude-opus-5
  reviewer: qwen2.5-coder:32b
  exploit_dev: anthropic/claude-opus-5
```

The reviewer-on-a-different-provider pattern is specifically called
out in Acuario's source-hunt design: independence between the
primary analyzer and the adversarial reviewer comes from *tier* rather
than provider by default, but splitting them across providers gives
the strongest independence guarantee.

## Model capability checklist

Acuario's agents REQUIRE the backing model to support:

- **Function calling / tool use** - the ReAct loop needs
  `bind_tools()` to work, which means the model has to support the
  OpenAI `tools: [...]` or Anthropic `tools: [...]` schema. Confirm
  with your provider's docs before running.
- **Multi-turn conversations with system prompts** - every provider
  listed above supports this. Mentioned here for completeness.
- **Token budget ≥ 32k context** - smaller contexts cause the ReAct
  loop to thrash as the conversation history grows. 128k+ is
  recommended.

Models known to work. The current Claude 5-family (`claude-opus-5`,
`claude-sonnet-5`, `claude-fable-5-1`, `claude-haiku-4-5-20251001`) and the
current GPT-5.x/6 models use the identical config; the list below is the set
originally exercised during development:

- Anthropic: `claude-opus-4-7`, `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`
- OpenRouter: any `anthropic/*`, `openai/gpt-4o`, `openai/gpt-4o-mini`
- OpenAI direct: `gpt-4o`, `gpt-4o-mini`, `o1-preview` (no tool calling on o1)
- Ollama (qwen2.5-coder:32b, llama3.3:70b with function-calling prompts)
- Groq: `llama-3.3-70b-versatile`, `qwen-2.5-coder-32b`
- Together: `meta-llama/Meta-Llama-3.3-70B-Instruct-Turbo`

If a model Acuario hits doesn't support tool calling, the first
tool dispatch will fail with a LangChain `tool_calls` attribute
error. That's not a Acuario bug - pick a different model.

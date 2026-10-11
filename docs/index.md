# Acuario

Inspired by Anthropic's Glasswing.

**Multi AI Agent Source Code Auditing Sandbox.** Built on
`genai-pyo3`, a native Rust-backed LLM runtime that speaks every major
provider (Anthropic, OpenAI, OpenRouter, Ollama, LM Studio, Together,
Groq, DeepSeek, MiniMax, or any OpenAI-compatible endpoint; Gemini is
reached via OpenRouter or a custom OpenAI-compatible endpoint).

Acuario does one thing: **find vulnerabilities in source code**. A
sandboxed analyzer agent runs per-file, an adversarial reviewer
validates each finding, an optional exploit-dev agent generates and
runs proofs-of-concept inside the sandbox, a deterministic SCA pass flags
known-vulnerable dependencies, and the reporter writes
SARIF + Markdown + JSON + a native PDF.

## Pages

| Page | What you'll learn |
|---|---|
| [**Quickstart**](quickstart.md) | Install, configure credentials, run your first audit, resume a crashed run, inspect past audits |
| [**LLM providers**](providers.md) | Anthropic / OpenAI / OpenRouter / Ollama / LM Studio / vLLM / Together / Groq / DeepSeek / MiniMax - CLI + env + config.yaml recipes, plus per-task routing |
| [**CLI reference**](cli.md) | Every flag for every command (`audit`, `setup`, `doctor`, `config`, `history`, `report`, `sessions`, `inspect`, `eval`) |
| [**Architecture**](architecture.md) | Pipeline internals - preprocessor, prioritizer, analyzer pool, reviewer, variant loop, exploit-dev, stability, reporter, plus sandbox + LLM + persistence layers |

## Authorized use

- Acuario is an offensive-security tool. Run it only against code you
  own or have explicit written authorization to audit.
- It surfaces candidate findings - triage and fix decisions stay with
  humans. Acuario does **not** patch source code.

## Reporting

- Vulnerabilities **in** Acuario → report privately via the repo's
  GitHub Security Advisories tab, or email opensource@dsci.in.
- Vulnerabilities Acuario **finds** in someone else's code → that
  vendor's disclosure channel.

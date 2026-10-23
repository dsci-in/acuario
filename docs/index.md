# Acuario

Acuario finds security bugs in source code by running a team of language-model
agents inside throwaway Docker sandboxes, rather than a single model reading
files in order. A per-file analyzer proposes findings, an adversarial reviewer
argues against each one, and verified bugs can be driven to a proof of concept
that runs in the sandbox. A deterministic dependency scan flags known-vulnerable
packages, and the reporter writes SARIF, Markdown, JSON, and a print-ready PDF.

Acuario is provider-agnostic: the model behind the agents is yours to choose,
any major commercial API or a server you run, set up through the `acuario setup`
wizard. The agentic approach was
prompted by Anthropic's Glasswing; Acuario is an independent, openly available
build of it. The [README](https://github.com/dsci-in/acuario#readme) has the
full picture.

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

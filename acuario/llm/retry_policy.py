"""Centralized LLM-error retry classification.

A single flat list of markers would conflate two very different failure modes:

- **Transient** connectivity blips (stream resets, 502/503, timeouts).
  Worth retrying with exponential backoff - they usually clear.
- **Request errors** - a malformed-request 4xx the server rejects
  deterministically. Retrying the *identical* body just burns the whole
  backoff budget before failing anyway.

The classifier returns one of ``"rate-limited" | "transient" | "request-error"
| None`` and a recommended attempt budget per category, so the retry loop can
fail fast on request errors (one cautious retry in case of a true one-off
blip) while still grinding through transient outages.
"""

from __future__ import annotations

# --- Marker tables -----------------------------------------------------------

#: Substrings indicating a transient connectivity blip - retry with backoff.
TRANSIENT_NET_MARKERS: tuple[str, ...] = (
    "web stream error",
    "error sending request",
    "connection reset",
    "connection refused",
    "connection aborted",
    "connection closed",
    "broken pipe",
    "timed out",
    "timeout",
    "temporary failure",
    "name or service not known",
    "no route to host",
    "network is unreachable",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
    " 502",
    " 503",
    " 504",
)

#: Substrings of HTTP 429 / explicit rate-limit responses - retry with backoff
#: (the retry-after honoring lives in native.py's delay computation).
RATE_LIMIT_MARKERS: tuple[str, ...] = (
    " 429",
    "rate limit",
    "rate-limit",
    "too many requests",
    "overloaded",
    "quota",
)

#: Substrings that mean "this exact request is broken" - the server rejects it
#: deterministically. Retrying the identical body cannot help, so these get a
#: single cautious retry at most (REQUEST_ERROR_MAX_ATTEMPTS), never the full
#: backoff budget. Schema/marshalling 400s and context overflows live here.
REQUEST_ERROR_MARKERS: tuple[str, ...] = (
    # Minijinja chat-template error from the self-hosted gateway when it can't
    # render the request (observed on exploit-dev tool-call turns, vLLM/SGLang
    # path). Deterministic per input - never recovers on retry.
    "can only get item pairs from a mapping",
    # Context-length overflows: the prompt is too long; identical retry fails.
    "maximum context length",
    "context length is",
    "context_length_exceeded",
    "input_tokens",
    "string too long",
    # Generic malformed-request signatures.
    "invalid_request_error",
    "unsupported value",
    "decoding seccomp",  # belt-and-suspenders; not LLM but a 400-shaped reject
)

# --- Attempt budgets ---------------------------------------------------------

#: Request errors get one cautious retry (handles a true one-off blip that
#: happens to share a substring) but never the full transient budget.
REQUEST_ERROR_MAX_ATTEMPTS: int = 1


# --- Classification ----------------------------------------------------------

# Retry categories, in priority order. Request-error wins over transient even
# when a body contains both signatures (a 400 that mentions "stream error" is
# still a 400 the server won't accept on retry).
KIND_REQUEST_ERROR = "request-error"
KIND_RATE_LIMITED = "rate-limited"
KIND_TRANSIENT = "transient network error"


def classify_error(exc: BaseException | str) -> str | None:
    """Classify an LLM error into a retry category.

    Returns one of :data:`KIND_REQUEST_ERROR`, :data:`KIND_RATE_LIMITED`,
    :data:`KIND_TRANSIENT`, or ``None`` (not retryable / unknown - caller
    should surface it).

    Request errors are checked *first* so a deterministic 4xx is never
    misclassified as a transient blip just because both substrings appear.
    """
    text = (exc if isinstance(exc, str) else str(exc)).lower()
    if any(m in text for m in REQUEST_ERROR_MARKERS):
        return KIND_REQUEST_ERROR
    if any(m in text for m in RATE_LIMIT_MARKERS):
        return KIND_RATE_LIMITED
    if any(m in text for m in TRANSIENT_NET_MARKERS):
        return KIND_TRANSIENT
    return None


def max_attempts_for_kind(kind: str | None, *, default: int) -> int:
    """How many *additional* retries a category is allowed.

    Request errors get at most :data:`REQUEST_ERROR_MAX_ATTEMPTS`; everything
    else gets the caller's configured ``default`` (e.g. native.py's
    ``rate_limit_max_retries``).
    """
    if kind == KIND_REQUEST_ERROR:
        return min(REQUEST_ERROR_MAX_ATTEMPTS, default)
    return default

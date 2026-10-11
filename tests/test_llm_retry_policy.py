"""Tests for the shared LLM retry classifier (M1).

The key regression these lock in: the vLLM chat-template 400
"Can only get item pairs from a mapping" must be classified as a
*request error* (fail fast), NOT a transient blip (full backoff budget).
J1 had it backwards, so every occurrence burned ~65s of exponential
backoff before failing anyway.
"""

from __future__ import annotations

from acuario.llm.retry_policy import (
    KIND_RATE_LIMITED,
    KIND_REQUEST_ERROR,
    KIND_TRANSIENT,
    REQUEST_ERROR_MAX_ATTEMPTS,
    classify_error,
    max_attempts_for_kind,
)


class TestClassifyError:
    def test_vllm_template_400_is_request_error_not_transient(self):
        msg = (
            "Web stream error for model 'qwen3.6-coder (adapter: OpenAI)'. "
            "Cause: HTTP error. Status: 400 Bad Request. "
            'Body: {"error":{"message":"Can only get item pairs from a mapping."}}'
        )
        # Even though the body ALSO contains "web stream error" (a transient
        # marker), the request-error signature must win.
        assert classify_error(msg) == KIND_REQUEST_ERROR

    def test_context_overflow_is_request_error(self):
        assert classify_error("This model's maximum context length is 32768 tokens") == (
            KIND_REQUEST_ERROR
        )

    def test_stream_reset_is_transient(self):
        assert classify_error("connection reset by peer") == KIND_TRANSIENT

    def test_502_is_transient(self):
        assert classify_error("HTTP error. Status: 502 Bad Gateway") == KIND_TRANSIENT

    def test_429_is_rate_limited(self):
        assert classify_error("Status: 429 Too Many Requests") == KIND_RATE_LIMITED

    def test_unknown_error_is_none(self):
        assert classify_error("some totally unrelated ValueError") is None

    def test_accepts_exception_instances(self):
        exc = RuntimeError("Can only get item pairs from a mapping.")
        assert classify_error(exc) == KIND_REQUEST_ERROR

    def test_case_insensitive(self):
        assert classify_error("CAN ONLY GET ITEM PAIRS FROM A MAPPING") == KIND_REQUEST_ERROR


class TestMaxAttempts:
    def test_request_error_capped_to_one(self):
        # Even with a generous default budget, request errors fail fast.
        assert max_attempts_for_kind(KIND_REQUEST_ERROR, default=6) == REQUEST_ERROR_MAX_ATTEMPTS
        assert max_attempts_for_kind(KIND_REQUEST_ERROR, default=6) <= 1

    def test_request_error_never_exceeds_default(self):
        # If the caller's default is 0 (retries disabled), respect it.
        assert max_attempts_for_kind(KIND_REQUEST_ERROR, default=0) == 0

    def test_transient_gets_full_budget(self):
        assert max_attempts_for_kind(KIND_TRANSIENT, default=6) == 6

    def test_rate_limited_gets_full_budget(self):
        assert max_attempts_for_kind(KIND_RATE_LIMITED, default=6) == 6

    def test_none_gets_full_budget(self):
        # max_attempts is only consulted after a non-None classification, but
        # the function should still behave sanely for None.
        assert max_attempts_for_kind(None, default=6) == 6

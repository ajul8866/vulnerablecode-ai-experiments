import httpx
import pytest
from pydantic_ai.exceptions import ModelHTTPError

from agent.config import RetryPolicy
from agent.robustness import (
    TRANSIENT_EXCEPTIONS,
    CVSSNotExtractableError,
    InvalidOutputError,
    LLMUnavailableError,
    UnsupportedCVSSVersionError,
    VulnerabilityAgentError,
    with_retry,
)


def test_exception_hierarchy():
    assert issubclass(LLMUnavailableError, VulnerabilityAgentError)
    assert issubclass(InvalidOutputError, VulnerabilityAgentError)
    assert issubclass(CVSSNotExtractableError, InvalidOutputError)
    assert issubclass(UnsupportedCVSSVersionError, VulnerabilityAgentError)


def test_invalid_output_error_carries_raw_and_reason():
    err = InvalidOutputError(raw="{}", reason="missing field")
    assert err.raw == "{}"
    assert err.reason == "missing field"


def test_transient_exceptions_covers_network_and_model():
    assert httpx.TransportError in TRANSIENT_EXCEPTIONS
    assert httpx.TimeoutException in TRANSIENT_EXCEPTIONS
    assert ModelHTTPError in TRANSIENT_EXCEPTIONS


def test_with_retry_succeeds_after_transient(monkeypatch):
    # determinism: no real sleeps
    monkeypatch.setattr("agent.robustness.time.sleep", lambda *_: None)

    calls = {"n": 0}

    class Flaky:
        def __call__(self):
            calls["n"] += 1
            if calls["n"] < 2:
                raise httpx.ConnectError("boom")
            return calls["n"]

    decorated = with_retry(RetryPolicy(max_attempts=3, base_delay=0.0))(Flaky())
    assert decorated() == calls["n"] == 2


def test_with_retry_gives_up_after_max_attempts(monkeypatch):
    monkeypatch.setattr("agent.robustness.time.sleep", lambda *_: None)
    calls = {"n": 0}

    def always_fail():
        calls["n"] += 1
        raise httpx.ReadTimeout("boom")

    decorated = with_retry(RetryPolicy(max_attempts=3, base_delay=0.0))(always_fail)
    with pytest.raises(LLMUnavailableError):
        decorated()
    assert calls["n"] == 3


def test_with_retry_does_not_retry_non_transient(monkeypatch):
    monkeypatch.setattr("agent.robustness.time.sleep", lambda *_: None)
    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise ValueError("not transient")

    decorated = with_retry(RetryPolicy(max_attempts=3))(boom)
    with pytest.raises(ValueError):
        decorated()
    assert calls["n"] == 1  # no retries

#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Robustness primitives: exceptions and retry/backoff."""

import random
import time
from functools import wraps
from typing import Callable, Tuple, TypeVar

import httpx
from pydantic_ai.exceptions import ModelHTTPError

from agent.config import RetryPolicy

T = TypeVar("T")


class VulnerabilityAgentError(Exception):
    """Base class for all errors raised by VulnerabilityAgent."""


class LLMUnavailableError(VulnerabilityAgentError):
    """Raised when transient LLM/network errors persist beyond the retry policy."""


class InvalidOutputError(VulnerabilityAgentError):
    """Raised when LLM output fails validation, even after a self-correction retry."""

    def __init__(self, raw: str, reason: str):
        self.raw = raw
        self.reason = reason
        super().__init__(f"Invalid LLM output ({reason}): {raw!r}")


class CVSSNotExtractableError(InvalidOutputError):
    """Raised when a CVSS vector cannot be obtained from regex or LLM."""


class UnsupportedCVSSVersionError(VulnerabilityAgentError):
    """Raised when a CVSS vector uses an unsupported version (e.g. CVSS:2)."""


# Exceptions considered transient and therefore retryable.
TRANSIENT_EXCEPTIONS: Tuple[type, ...] = (
    ModelHTTPError,
    httpx.TransportError,
    httpx.TimeoutException,
    httpx.NetworkError,
)


def _sleep_delay(policy: RetryPolicy, attempt: int) -> float:
    """Exponential backoff with jitter, capped at policy.max_delay."""
    delay = min(policy.max_delay, policy.base_delay * (2 ** (attempt - 1)))
    return delay * (0.5 + 0.5 * random.random())


def with_retry(policy: RetryPolicy) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorate a callable to retry transient exceptions per ``policy``."""

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exc = None
            for attempt in range(1, policy.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except TRANSIENT_EXCEPTIONS as exc:
                    last_exc = exc
                    if attempt < policy.max_attempts:
                        time.sleep(_sleep_delay(policy, attempt))
                    continue
            raise LLMUnavailableError(
                f"LLM unavailable after {policy.max_attempts} attempts"
            ) from last_exc

        return wrapper

    return decorator

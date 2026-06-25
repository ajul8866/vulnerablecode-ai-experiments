# CVSS Parser + Robustness Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a hybrid CVSS parser (regex-first, LLM fallback, score computed from the vector) and a thorough robustness layer (retry+backoff, validation, normalization, single self-correction retry) applied to every existing parser plus the new CVSS parser.

**Architecture:** A centralized pipeline in `BaseParser` (preprocess → run_with_retry → validate → normalize) with optional per-parser hooks. The CVSS parser supplies a `preprocess` hook (regex extraction) and a `normalize` hook (score computation via the `cvss` lib). Refactor the current single-file `agent/__init__.py` into focused modules under `agent/` with public re-exports preserved.

**Tech Stack:** Python 3.14, `pydantic` 2.13, `pydantic-ai` 1.6.0 (uses `httpx` 0.28.1), `cvss` 3.x (PyPI: `cvss`), `univers`, `packageurl-python`, `aboutcode-hashid`, `cwe2`, `pytest` 8.4.2. No new test framework; `pydantic_ai.models.function.FunctionModel` is used as a mock LLM.

## Global Constraints

- **CVSS versions supported:** 3.1 and 4.0 only. CVSS:2 is rejected with `UnsupportedCVSSVersionError`. (Spec §4, §10)
- **Score source:** `base_score` is ALWAYS computed from the vector via the `cvss` library — never asked of the LLM, never guessed. (Spec §4 normalize stage)
- **CVSS extraction order:** regex first; LLM is invoked ONLY when regex finds nothing valid. (Spec §4)
- **Public contract preserved:** every existing `VulnerabilityAgent` method keeps its name, signature, and return type. `agent/__init__.py` must keep re-exporting all public names. (Spec §5)
- **New deps:** `cvss` added to `requirements.txt`. Retry is implemented with stdlib (`time.sleep`) — **no `tenacity`**. (Spec §7 — resolved here in favor of stdlib)
- **Determinism:** plain `pytest` must never call a live LLM. Live LLM tests carry `@pytest.mark.live` and are excluded by default. (Spec §6)
- **All exceptions** raised by the agent hierarchy subclass `VulnerabilityAgentError`. (Spec §4)
- **Retry defaults:** `max_attempts=3`, `base_delay=0.1`s, `max_delay=2.0`s, exponential backoff + jitter. (Spec §4)

---

## File Structure

| Path | Responsibility | Action |
|---|---|---|
| `agent/__init__.py` | Public re-exports + `VulnerabilityAgent` facade. Contract preserved. | Rewrite (re-export from new modules) |
| `agent/config.py` | Load `OPENAI_*` env vars; define `RetryPolicy` default. | Create |
| `agent/robustness.py` | Exception hierarchy + `RetryPolicy` + `with_retry`. | Create |
| `agent/models.py` | `Purl`, `CWE`, `CWEList`, `Severity`, `SeverityEnum`, `Versions` (moved) + `CVSSVector` (new). | Create |
| `agent/pipeline.py` | `run_pipeline`: preprocess → run_with_retry → validate → normalize, with single self-correction. | Create |
| `agent/cvss_extraction.py` | `extract_cvss_vector(text) -> Optional[str]` — regex + cvss validation. | Create |
| `agent/parsers/__init__.py` | Package marker. | Create |
| `agent/parsers/base.py` | `BaseParser` composing the pipeline; optional hooks. | Create |
| `agent/parsers/purl_from_summary.py` | Existing parser, moved. | Create |
| `agent/parsers/purl_from_cpe.py` | Existing parser, moved. | Create |
| `agent/parsers/versions.py` | Existing parser, moved. | Create |
| `agent/parsers/severity.py` | Existing parser, moved. | Create |
| `agent/parsers/cwe.py` | Existing parser, moved. | Create |
| `agent/parsers/cvss.py` | New CVSS parser (preprocess=regex, normalize=score). | Create |
| `prompts.py` | Add `PROMPT_CVSS_FROM_SUMMARY`. | Modify |
| `requirements.txt` | Add `cvss`. | Modify |
| `conftest.py` | Register `live` marker; default `addopts = -m "not live"`. | Create |
| `pyproject.toml` | Minimal `[tool.pytest.ini_options]` (no existing config). | Create |
| `test.py` | Mark existing tests `@pytest.mark.live`; keep them intact. | Modify |
| `tests/` (new dir) | Deterministic tests for new code. | Create per task |

---

## Task 1: Scaffolding — `pyproject.toml`, `conftest.py`, and `cvss` dependency

**Files:**
- Create: `pyproject.toml`
- Create: `conftest.py`
- Modify: `requirements.txt`

**Interfaces:**
- Produces: a `pytest` run that discovers tests and skips `live` by default; `cvss` importable.

- [ ] **Step 1: Add `cvss` to requirements**

Final `requirements.txt` content (append `cvss`):
```
aboutcode-hashid==0.2.0
python-dotenv==1.2.1
packageurl-python==0.17.5
pydantic==2.12.3
pydantic-ai==1.6.0
univers==31.1.0
pytest==8.4.2
cwe2==3.0.0
cvss==3.0
```

- [ ] **Step 2: Create `pyproject.toml`** (minimal pytest config only; this repo has no packaging config today and none is required by the spec)

```toml
[tool.pytest.ini_options]
markers = [
    "live: tests that call a real LLM (excluded by default; run with -m live)",
]
addopts = "-m 'not live'"
testpaths = ["test.py", "tests"]
```

- [ ] **Step 3: Create `conftest.py`** (root — registers the marker defensively in case `pyproject.toml` is not picked up)

```python
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: tests that call a real LLM (excluded by default; run with -m live)",
    )
```

- [ ] **Step 4: Install the new dependency**

Run: `.venv/bin/pip install cvss==3.0` (or recreate venv from `requirements.txt`).

- [ ] **Step 5: Verify pytest still works and skips nothing yet**

Run: `.venv/bin/pytest --co -q`
Expected: collects `test.py` tests without error (they have no marker yet; they will be marked in Task 12). No failures.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml conftest.py requirements.txt
git commit -m "build: add cvss dep and pytest live marker scaffolding"
```

---

## Task 2: `agent/config.py` — env config + `RetryPolicy`

**Files:**
- Create: `agent/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `load_openai_config() -> OpenAIConfig` and dataclass `OpenAIConfig(api_base, api_key, model_name, temperature, model_seed)`; `RetryPolicy` dataclass with fields `max_attempts:int=3`, `base_delay:float=0.1`, `max_delay:float=2.0`; constant `DEFAULT_RETRY_POLICY = RetryPolicy()`.

- [ ] **Step 1: Write failing test**

`tests/test_config.py`:
```python
from agent.config import OpenAIConfig, RetryPolicy, DEFAULT_RETRY_POLICY


def test_retry_policy_defaults():
    p = RetryPolicy()
    assert p.max_attempts == 3
    assert p.base_delay == 0.1
    assert p.max_delay == 2.0


def test_default_retry_policy_singleton():
    assert DEFAULT_RETRY_POLICY.max_attempts == 3


def test_openai_config_reads_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_BASE", "https://example.test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("OPENAI_TEMPERATURE", "0.25")
    monkeypatch.setenv("OPENAI_MODEL_SEED", "12345")
    cfg = OpenAIConfig.from_env()
    assert cfg.api_base == "https://example.test"
    assert cfg.api_key == "sk-test"
    assert cfg.model_name == "gpt-test"
    assert cfg.temperature == 0.25
    assert isinstance(cfg.temperature, float)
    assert cfg.model_seed == 12345
    assert isinstance(cfg.model_seed, int)
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.config'`.

- [ ] **Step 3: Implement `agent/config.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Configuration: OpenAI-compatible LLM settings and retry policy."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    """Retry/backoff parameters for transient LLM failures."""

    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 2.0


DEFAULT_RETRY_POLICY = RetryPolicy()


@dataclass(frozen=True)
class OpenAIConfig:
    api_base: str
    api_key: str
    model_name: str
    temperature: float
    model_seed: int

    @classmethod
    def from_env(cls) -> "OpenAIConfig":
        return cls(
            api_base=os.getenv("OPENAI_API_BASE"),
            api_key=os.getenv("OPENAI_API_KEY"),
            model_name=os.getenv("OPENAI_MODEL_NAME"),
            temperature=float(os.getenv("OPENAI_TEMPERATURE", 0.3)),
            model_seed=int(os.getenv("OPENAI_MODEL_SEED", 11111111)),
        )
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/config.py tests/test_config.py
git commit -m "feat(config): add OpenAIConfig and RetryPolicy"
```

---

## Task 3: `agent/robustness.py` — exception hierarchy + `with_retry`

**Files:**
- Create: `agent/robustness.py`
- Test: `tests/test_robustness.py`

**Interfaces:**
- Produces:
  - `VulnerabilityAgentError(Exception)` — base.
  - `LLMUnavailableError(VulnerabilityAgentError)` — transient errors exhausted.
  - `InvalidOutputError(VulnerabilityAgentError)` — output fails validation after self-correction. Carries `.raw` and `.reason`.
  - `CVSSNotExtractableError(InvalidOutputError)`.
  - `UnsupportedCVSSVersionError(VulnerabilityAgentError)`.
  - `TRANSIENT_EXCEPTIONS` tuple = `(ModelHTTPError, httpx.TransportError, httpx.TimeoutException, httpx.NetworkError)`.
  - `with_retry(policy: RetryPolicy) -> Callable` decorator factory.
- Consumes: `RetryPolicy`, `DEFAULT_RETRY_POLICY` from `agent.config`.

- [ ] **Step 1: Write failing test**

`tests/test_robustness.py`:
```python
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
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_robustness.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.robustness'`.

- [ ] **Step 3: Implement `agent/robustness.py`**

```python
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
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_robustness.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/robustness.py tests/test_robustness.py
git commit -m "feat(robustness): add exception hierarchy and retry decorator"
```

---

## Task 4: `agent/models.py` — moved pydantic models + `CVSSVector`

**Files:**
- Create: `agent/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Purl`, `CWE`, `CWEList`, `Severity`, `SeverityEnum`, `Versions` (moved verbatim from `agent/__init__.py`), plus `CVSSVector`.
- `CVSSVector(BaseModel)` fields: `vector: str`, `version: Literal["3.1", "4.0"]`, `base_score: float`, `severity_label: str`.
- `CVSSVector` validator `check_valid_cvss` runs on the `vector` field: rejects `CVSS:2` → `UnsupportedCVSSVersionError`; otherwise constructs `cvss.CVSS3`/`CVSS4` to confirm validity, and on failure raises `ValueError`.
- `CVSSVector.from_vector(vector_str)` classmethod: parses version from prefix, validates, and fills `base_score` + `severity_label` from the `cvss` lib. (Used by the regex path and by normalize.)

> **Note:** `CWE_DATABASE = Database()` requires the `cwe2` data to be present at import time. The current `agent/__init__.py` already imports it at module top, so moving it into `agent/models.py` preserves existing behavior.

- [ ] **Step 1: Write failing test**

`tests/test_models.py`:
```python
import pytest
from pydantic import ValidationError

from agent.models import CVSSVector
from agent.robustness import UnsupportedCVSSVersionError


def test_cvss_vector_from_valid_v31():
    v = CVSSVector.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert v.version == "3.1"
    assert v.base_score == pytest.approx(7.5)
    assert v.severity_label.lower() == "high"


def test_cvss_vector_from_valid_v40():
    v = CVSSVector.from_vector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    )
    assert v.version == "4.0"
    assert v.base_score == pytest.approx(8.7)
    assert v.severity_label.lower() == "high"


def test_cvss_vector_rejects_v2():
    with pytest.raises(UnsupportedCVSSVersionError):
        CVSSVector.from_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P")


def test_cvss_vector_rejects_invalid_metric():
    with pytest.raises((ValidationError, ValueError)):
        CVSSVector.from_vector("CVSS:3.1/AV:BOGUS/AC:L")


def test_cvss_vector_validator_runs_on_field():
    # constructing directly also validates the vector field
    v = CVSSVector(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        version="3.1",
        base_score=0.0,
        severity_label="low",
    )
    assert v.vector.startswith("CVSS:3.1")
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.models'`.

- [ ] **Step 3: Implement `agent/models.py`**

Move the existing model classes (`Purl`, `CWE`, `CWEList`, `SeverityEnum`, `Severity`, `Versions`, and the `CWE_DATABASE = Database()` line) verbatim from the current `agent/__init__.py` (lines producing those classes). Then add `CVSSVector`.

> **Critical correctness note:** the `cvss` library raises `CVSS3MalformedError` (a plain `Exception`, NOT a `ValueError`) for invalid metrics, and pydantic does NOT wrap non-`ValueError` exceptions from validators into `ValidationError`. Therefore `check_valid_cvss` and `from_vector` MUST catch `Exception` from `CVSS3(...)`/`CVSS4(...)` and re-raise as `ValueError`, so that (a) pydantic produces a proper `ValidationError` (which the pipeline uses to trigger self-correction), and (b) `from_vector`'s failure mode is predictable. Verified against `cvss` 3.0 + pydantic 2.13.

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Pydantic output models for vulnerability parsers."""

from enum import Enum
from typing import List, Literal

from cwe2.database import Database
from packageurl import PackageURL
from pydantic import BaseModel, field_validator

from agent.robustness import UnsupportedCVSSVersionError

CWE_DATABASE = Database()


class Purl(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_purl(cls, purl: str) -> str:
        PackageURL.from_string(purl)
        return purl


class CWE(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_cwe(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm.startswith("CWE-"):
            norm = norm[4:].strip()
        if not norm.isdigit():
            raise ValueError("CWE must be a numeric identifier, e.g., 'CWE-79' or '79'")
        CWE_DATABASE.get(norm)
        return f"CWE-{norm}"


class CWEList(BaseModel):
    cwes: List[CWE]


class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Severity(BaseModel):
    severity: SeverityEnum


class Versions(BaseModel):
    affected_versions: List[str]
    fixed_versions: List[str]


def _cvss_class_for(prefix: str):
    from cvss import CVSS3, CVSS4

    if prefix in ("CVSS:3.0", "CVSS:3.1"):
        return CVSS3
    if prefix == "CVSS:4.0":
        return CVSS4
    return None


def _parse_cvss_or_raise(vector: str):
    """Construct the cvss parser object, re-raising any error as ValueError."""
    from cvss import CVSS3, CVSS4

    stripped = vector.strip()
    prefix = stripped.split("/", 1)[0]
    klass = _cvss_class_for(prefix)
    if klass is None:
        # Genuine v2 vectors (no CVSS:3./4. prefix) or "Au:" shape => unsupported.
        if not stripped.startswith(("CVSS:3.", "CVSS:4.")):
            raise UnsupportedCVSSVersionError(
                f"Unsupported CVSS version (only 3.1 and 4.0): {vector!r}"
            )
        raise ValueError(f"Invalid CVSS vector: {vector!r}")
    try:
        return klass(stripped)
    except UnsupportedCVSSVersionError:
        raise
    except Exception as exc:  # CVSS3MalformedError etc. -> ValueError for pydantic
        raise ValueError(f"Invalid CVSS vector: {vector!r}") from exc


class CVSSVector(BaseModel):
    vector: str
    version: Literal["3.1", "4.0"]
    base_score: float
    severity_label: str

    @field_validator("vector")
    @classmethod
    def check_valid_cvss(cls, v: str) -> str:
        _parse_cvss_or_raise(v)  # raises ValueError / UnsupportedCVSSVersionError
        return v.strip()

    @classmethod
    def from_vector(cls, vector_str: str) -> "CVSSVector":
        parsed = _parse_cvss_or_raise(vector_str)
        stripped = vector_str.strip()
        version = "4.0" if stripped.split("/", 1)[0] == "CVSS:4.0" else "3.1"
        # cvss 3.0 API differs between classes: base_score is an attribute on both;
        # CVSS3 exposes severities(), CVSS4 exposes a `severity` attribute instead.
        base_score = float(parsed.base_score)
        if version == "4.0":
            severity_label = str(parsed.severity).lower()
        else:
            severity_label = str(parsed.severities()[0]).lower()
        return cls(
            vector=stripped,
            version=version,
            base_score=base_score,
            severity_label=severity_label,
        )
```

> **Note on `UnsupportedCVSSVersionError` inside a pydantic validator:** it is a `VulnerabilityAgentError` (subclass of `Exception`, not `ValueError`), so pydantic will NOT wrap it into `ValidationError` — it propagates as-is. That is the intended behavior for v2 vectors: callers get a typed `UnsupportedCVSSVersionError` rather than a generic validation error. Only the "malformed metric" path is converted to `ValueError` (→ `ValidationError`), which is what drives self-correction.

> **cvss 3.0 API note (verified):** `base_score` is an attribute (Decimal on `CVSS3`, float on `CVSS4`) on both classes — use `float(parsed.base_score)`. Severity access differs: `CVSS3.severities()[0]` vs `CVSS4.severity` (attribute). `CVSS4` has NO `scores()`/`severities()` methods. `clean_vector()` exists on both.

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_models.py -v`
Expected: PASS (5 tests). If `cwe2.Database()` fails to initialize at import, ensure `cwe2` data is installed (it is already a dependency); this is pre-existing behavior.

- [ ] **Step 5: Commit**

```bash
git add agent/models.py tests/test_models.py
git commit -m "feat(models): move pydantic models to models.py and add CVSSVector"
```

---

## Task 5: `agent/cvss_extraction.py` — regex extraction + validation

**Files:**
- Create: `agent/cvss_extraction.py`
- Test: `tests/test_cvss_extraction.py`

**Interfaces:**
- Produces: `extract_cvss_vector(text: str) -> Optional[str]` — returns a validated, `clean_vector()`-normalized CVSS 3.1/4.0 string, or `None` if no valid vector is found. Internally uses regex to find candidate substrings then validates each with the `cvss` lib.

- [ ] **Step 1: Write failing test**

`tests/test_cvss_extraction.py`:
```python
from agent.cvss_extraction import extract_cvss_vector


def test_extracts_v31_inline():
    text = (
        "The issue is fixed in v1.2.3. The CVSS score is 7.5 "
        "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) high severity."
    )
    assert (
        extract_cvss_vector(text)
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    )


def test_extracts_v40():
    text = "Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert extract_cvss_vector(text) == text.split("Vector: ", 1)[1]


def test_returns_none_when_no_vector():
    assert extract_cvss_vector("A bug was found in ansible. No vector here.") is None


def test_ignores_invalid_candidate_and_keeps_looking():
    # one bogus metric value, then a valid one
    text = (
        "bad: CVSS:3.1/AV:BOGUS/AC:L ; "
        "good: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    )
    assert extract_cvss_vector(text) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def test_ignores_cvss2():
    # v2 vectors are not surfaced by the regex (require CVSS:3./4. prefix)
    assert extract_cvss_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P") is None
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_cvss_extraction.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.cvss_extraction'`.

- [ ] **Step 3: Implement `agent/cvss_extraction.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Regex-based extraction of CVSS vectors (the 'regex first' half of the hybrid)."""

import re
from typing import Optional

# Match CVSS:3.x or CVSS:4.0 vector strings. Slashes are required to be present.
_CVSS_RE = re.compile(r"CVSS:(?:3\.[01]|4\.0)/[A-Za-z0-9:/_.\-]+")

# Hard cap on candidate length to avoid runaway matches.
_MAX_CANDIDATE_LEN = 512


def extract_cvss_vector(text: str) -> Optional[str]:
    """Return a validated, normalized CVSS 3.1/4.0 vector found in ``text``, or None."""
    if not text:
        return None
    for candidate in _CVSS_RE.findall(text):
        candidate = candidate[:_MAX_CANDIDATE_LEN]
        normalized = _validate(candidate)
        if normalized is not None:
            return normalized
    return None


def _validate(candidate: str) -> Optional[str]:
    from cvss import CVSS3, CVSS4

    prefix = candidate.split("/", 1)[0]
    klass = CVSS4 if prefix == "CVSS:4.0" else CVSS3
    try:
        parsed = klass(candidate)
    except Exception:
        return None
    return parsed.clean_vector()
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_cvss_extraction.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/cvss_extraction.py tests/test_cvss_extraction.py
git commit -m "feat(cvss): add regex-first vector extractor"
```

---

## Task 6: `agent/pipeline.py` — run pipeline (preprocess → retry → normalize)

**Files:**
- Create: `agent/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Produces:
  - `PipelineHooks` dataclass with `preprocess: Optional[Callable[[str], str]] = None` and `normalize: Optional[Callable[[Any], Any]] = None`.
  - `run_pipeline(*, run_fn: Callable[[str], TResult], user_prompt: str, output_type: type, hooks: PipelineHooks, retry_policy: RetryPolicy) -> TResult` where:
    - `run_fn(prompt) -> TResult` is the (un-decorated) LLM call returning a pydantic model instance.
    - preprocess hook, if set, may rewrite the prompt (the CVSS parser injects regex context / a "vector already known" instruction).
    - **Output validation + self-correction is handled by pydantic-ai itself** via the Agent's `output_retries` (set in Task 7). When validation ultimately fails, `run_fn` raises `UnexpectedModelBehavior`, which this pipeline maps to `InvalidOutputError`. (Verified against pydantic-ai 1.6.0: exhausting `output_retries` raises `pydantic_ai.exceptions.UnexpectedModelBehavior`.)
    - normalize hook transforms the validated result (CVSS: fill `base_score`/`severity_label`).
    - `with_retry(retry_policy)` wraps `run_fn` for **transient** errors only.
- Consumes: `with_retry`, `InvalidOutputError`, `RetryPolicy` from `agent.config`/`agent.robustness`.

> **Design note (revised after API verification):** the original design proposed a manual self-correction retry in the pipeline. That duplicates pydantic-ai's built-in `output_retries`, which already feeds validation errors back to the model. We therefore rely on pydantic-ai for self-correction and only translate its terminal `UnexpectedModelBehavior` into our typed `InvalidOutputError`. Transient retry remains ours (pydantic-ai does not retry network/HTTP errors by default).

- [ ] **Step 1: Write failing test**

`tests/test_pipeline.py`:
```python
import pytest
from pydantic import BaseModel
from pydantic_ai.exceptions import UnexpectedModelBehavior

from agent.config import RetryPolicy
from agent.pipeline import PipelineHooks, run_pipeline
from agent.robustness import InvalidOutputError


class Out(BaseModel):
    name: str


def test_pipeline_happy_path():
    def run_fn(prompt):
        return Out(name="ok")

    res = run_pipeline(
        run_fn=run_fn,
        user_prompt="hi",
        output_type=Out,
        hooks=PipelineHooks(),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    assert res == Out(name="ok")


def test_pipeline_maps_unexpected_model_behavior_to_invalid_output():
    def run_fn(prompt):
        # pydantic-ai raises this when output_retries are exhausted on bad output.
        raise UnexpectedModelBehavior("Exceeded maximum retries for output validation")

    with pytest.raises(InvalidOutputError):
        run_pipeline(
            run_fn=run_fn,
            user_prompt="hi",
            output_type=Out,
            hooks=PipelineHooks(),
            retry_policy=RetryPolicy(max_attempts=1),
        )


def test_pipeline_preprocess_hook_applied():
    seen = {}

    def run_fn(prompt):
        seen["prompt"] = prompt
        return Out(name="ok")

    run_pipeline(
        run_fn=run_fn,
        user_prompt="base",
        output_type=Out,
        hooks=PipelineHooks(preprocess=lambda p: p + " +context"),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    assert seen["prompt"] == "base +context"


def test_pipeline_normalize_hook_applied():
    def run_fn(prompt):
        return Out(name="raw")

    res = run_pipeline(
        run_fn=run_fn,
        user_prompt="hi",
        output_type=Out,
        hooks=PipelineHooks(normalize=lambda r: Out(name=r.name + "+norm")),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    assert res == Out(name="raw+norm")
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_pipeline.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.pipeline'`.

- [ ] **Step 3: Implement `agent/pipeline.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""The centralized parser pipeline: preprocess -> run -> normalize."""

from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

from pydantic_ai.exceptions import UnexpectedModelBehavior

from agent.config import RetryPolicy
from agent.robustness import InvalidOutputError, with_retry

TResult = TypeVar("TResult")


@dataclass
class PipelineHooks:
    preprocess: Optional[Callable[[str], str]] = None
    normalize: Optional[Callable[[Any], Any]] = None


def run_pipeline(
    *,
    run_fn: Callable[[str], TResult],
    user_prompt: str,
    output_type: type,
    hooks: PipelineHooks,
    retry_policy: RetryPolicy,
) -> TResult:
    """Run the parser pipeline: preprocess, retry transient failures, normalize.

    Output validation and the self-correction retry are handled inside the
    pydantic-ai Agent (via ``output_retries``); a terminal failure surfaces as
    ``UnexpectedModelBehavior``, which we translate to ``InvalidOutputError``.
    """
    if hooks.preprocess:
        user_prompt = hooks.preprocess(user_prompt)

    retried = with_retry(retry_policy)(run_fn)

    try:
        result = retried(user_prompt)
    except UnexpectedModelBehavior as err:
        raise InvalidOutputError(
            raw=user_prompt, reason="output failed validation after retries"
        ) from err

    if hooks.normalize:
        result = hooks.normalize(result)
    return result
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_pipeline.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/pipeline.py tests/test_pipeline.py
git commit -m "feat(pipeline): add centralized run pipeline using pydantic-ai output_retries"
```

---

## Task 7: `agent/parsers/base.py` — `BaseParser` composing the pipeline

**Files:**
- Create: `agent/parsers/__init__.py` (empty package marker)
- Create: `agent/parsers/base.py`
- Test: `tests/test_base_parser.py`

**Interfaces:**
- Produces: `BaseParser` with:
  - `__init__(self, system_prompt: str, output_type: type, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY)`.
  - builds `pydantic_ai.Agent` via `_build_agent(self, cfg: OpenAIConfig)` using `OpenAIChatModel` + `OpenAIProvider` + `OpenAIChatModelSettings(temperature, seed)`.
  - `run_agent(self, user_prompt: str) -> TResult` — runs the pipeline with this parser's hooks (default `PipelineHooks()`).
  - overridable `hooks(self) -> PipelineHooks` property returning `PipelineHooks()` (subclasses override).
  - `_raw_run(self, user_prompt: str) -> TResult` — the actual `self.agent.run_sync(user_prompt=user_prompt).output` call (wrapped by the pipeline's `with_retry`).
  - overridable `_build_agent(self, cfg)` so tests can inject a mock model.
- Consumes: `OpenAIConfig`, `RetryPolicy`, `DEFAULT_RETRY_POLICY` from `agent.config`; `run_pipeline`, `PipelineHooks` from `agent.pipeline`.

- [ ] **Step 1: Write failing test** (uses a stub agent so no LLM is called)

`tests/test_base_parser.py`:
```python
from typing import Any

from agent.config import RetryPolicy
from agent.parsers.base import BaseParser
from agent.pipeline import PipelineHooks


class Out:
    def __init__(self, value):
        self.value = value


class StubAgent:
    def __init__(self, output):
        self._output = output

    def run_sync(self, *, user_prompt):
        class R:
            output = self._output

        return R()


class StubParser(BaseParser):
    def __init__(self, output):
        self._output = output
        super().__init__("sys", Out, retry_policy=RetryPolicy(max_attempts=1))

    def _build_agent(self, cfg):
        return StubAgent(self._output)


def test_base_parser_runs_pipeline_and_returns_output():
    parser = StubParser(output=Out("hello"))
    assert parser.run_agent("prompt").value == "hello"


def test_base_parser_uses_subclass_hooks(monkeypatch):
    captured = {}

    class Hooked(StubParser):
        def hooks(self):
            return PipelineHooks(preprocess=lambda p: p + "!")

    parser = Hooked(output=Out("ok"))
    parser.run_agent("prompt")
    # The stub echoes a fixed output; preprocess is exercised via the pipeline path.
    assert parser._output.value == "ok"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_base_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.parsers'`.

- [ ] **Step 3: Implement `agent/parsers/__init__.py`** (empty):

```python
```

- [ ] **Step 4: Implement `agent/parsers/base.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Base parser composing the centralized pipeline."""

from typing import TypeVar

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from agent.config import DEFAULT_RETRY_POLICY, OpenAIConfig, RetryPolicy
from agent.pipeline import PipelineHooks, run_pipeline

TResult = TypeVar("TResult")


class BaseParser:
    def __init__(
        self,
        system_prompt: str,
        output_type: type,
        retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
    ):
        self._system_prompt = system_prompt
        self.retry_policy = retry_policy
        self.output_type = output_type
        self.agent = self._build_agent(OpenAIConfig.from_env())

    def _build_agent(self, cfg: OpenAIConfig) -> Agent:
        model = OpenAIChatModel(
            model_name=cfg.model_name,
            provider=OpenAIProvider(base_url=cfg.api_base, api_key=cfg.api_key),
        )
        return Agent(
            model,
            system_prompt=self._system_prompt,
            model_settings=OpenAIChatModelSettings(
                temperature=cfg.temperature, seed=cfg.model_seed
            ),
            output_type=self.output_type,
            # pydantic-ai handles self-correction: on a validation failure it feeds
            # the error back to the model and retries up to output_retries times
            # before raising UnexpectedModelBehavior (translated in run_pipeline).
            output_retries=1,
        )

    @property
    def hooks(self) -> PipelineHooks:
        return PipelineHooks()

    def _raw_run(self, user_prompt: str) -> TResult:
        return self.agent.run_sync(user_prompt=user_prompt).output

    def run_agent(self, user_prompt: str) -> TResult:
        return run_pipeline(
            run_fn=self._raw_run,
            user_prompt=user_prompt,
            output_type=self.output_type,
            hooks=self.hooks,
            retry_policy=self.retry_policy,
        )
```

> **Testing seam:** `BaseParser.__init__` calls `self._build_agent(OpenAIConfig.from_env())`. Tests subclass and override `_build_agent` to return a stub agent (see `tests/test_base_parser.py`), so no real LLM is constructed or called. `hooks` is defined as a `@property` returning a fresh `PipelineHooks()`; subclasses that need custom hooks override the property.

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_base_parser.py -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add agent/parsers/__init__.py agent/parsers/base.py tests/test_base_parser.py
git commit -m "feat(parsers): add BaseParser composing the pipeline"
```

---

## Task 8: Move existing parsers into `agent/parsers/*.py`

**Files:**
- Create: `agent/parsers/purl_from_summary.py`
- Create: `agent/parsers/purl_from_cpe.py`
- Create: `agent/parsers/versions.py`
- Create: `agent/parsers/severity.py`
- Create: `agent/parsers/cwe.py`

**Interfaces:**
- Each parser subclasses `BaseParser`, passes its `system_prompt` and `output_type`, accepts an optional `retry_policy` and forwards it to `super().__init__`, and keeps its public method + return type **identical** to the current implementation.
- Every parser module imports `from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy`.
- Consumes: `BaseParser` from `agent.parsers.base`; models from `agent.models`; prompts from `prompts`; helpers `get_core_purl` and `RANGE_CLASS_BY_SCHEMES` as today.
- Produces (signatures, unchanged from current code):
  - `PurlFromSummaryParser.get_purl(self, summary: str) -> Optional[PackageURL]`
  - `PurlFromCPEParser.get_purl(self, cpe: str, pkg_type) -> Optional[PackageURL]`
  - `VersionsFromSummaryParser.get_version_ranges(self, summary: str, supported_ecosystem: str)`
  - `SeverityFromSummaryParser.get_severity(self, summary: str) -> Optional[Severity]`
  - `CWEFromSummaryParser.get_cwes(self, summary: str) -> list[str]`

- [ ] **Step 1: Implement `agent/parsers/purl_from_summary.py`** (moved from current `__init__.py`)

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Extract a Package URL from a vulnerability summary."""

from typing import Optional

from aboutcode.hashid import get_core_purl
from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Purl
from agent.parsers.base import BaseParser
from prompts import PROMPT_PURL_FROM_SUMMARY


class PurlFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_PURL_FROM_SUMMARY, Purl, retry_policy=retry_policy)

    def get_purl(self, summary: str) -> Optional[PackageURL]:
        # run_agent returns the pydantic output model directly (Task 7 contract).
        output = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        purl = PackageURL.from_string(output.string)
        return get_core_purl(purl)
```

- [ ] **Step 2: Implement `agent/parsers/purl_from_cpe.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Extract a Package URL from a CPE identifier."""

from typing import Optional

from aboutcode.hashid import get_core_purl
from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Purl
from agent.parsers.base import BaseParser
from prompts import PROMPT_PURL_FROM_CPE


class PurlFromCPEParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_PURL_FROM_CPE, Purl, retry_policy=retry_policy)

    def get_purl(self, cpe: str, pkg_type) -> Optional[PackageURL]:
        output = self.run_agent(
            f"**Vulnerability Known Affected Software Configurations CPE:**\n{cpe}\n"
            f"**Package Type:**\n{pkg_type}"
        )
        purl = PackageURL.from_string(output.string)
        return get_core_purl(purl)
```

- [ ] **Step 3: Implement `agent/parsers/versions.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Extract affected/fixed version ranges from a summary."""

from univers.version_range import RANGE_CLASS_BY_SCHEMES

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Versions
from agent.parsers.base import BaseParser
from prompts import PROMPT_VERSION_FROM_SUMMARY


class VersionsFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_VERSION_FROM_SUMMARY, Versions, retry_policy=retry_policy)

    def get_version_ranges(self, summary: str, supported_ecosystem: str):
        output = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        affected_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in output.affected_versions
        ]
        fixed_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in output.fixed_versions
        ]
        return affected_objs, fixed_objs
```

- [ ] **Step 4: Implement `agent/parsers/severity.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Extract severity from a summary."""

from typing import Optional

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Severity
from agent.parsers.base import BaseParser
from prompts import PROMPT_SEVERITY_FROM_SUMMARY


class SeverityFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_SEVERITY_FROM_SUMMARY, Severity, retry_policy=retry_policy)

    def get_severity(self, summary: str) -> Optional[Severity]:
        output = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return output.severity.value
```

- [ ] **Step 5: Implement `agent/parsers/cwe.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Extract CWE IDs from a summary."""

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import CWEList
from agent.parsers.base import BaseParser
from prompts import PROMPT_CWE_FROM_SUMMARY


class CWEFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_CWE_FROM_SUMMARY, CWEList, retry_policy=retry_policy)

    def get_cwes(self, summary: str) -> list[str]:
        output = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return [cwe.string for cwe in output.cwes]
```

- [ ] **Step 6: Add an import-only smoke test** (verifies modules load and subclasses are correct)

`tests/test_parsers_import.py`:
```python
from agent.parsers.base import BaseParser
from agent.parsers.cwe import CWEFromSummaryParser
from agent.parsers.purl_from_cpe import PurlFromCPEParser
from agent.parsers.purl_from_summary import PurlFromSummaryParser
from agent.parsers.severity import SeverityFromSummaryParser
from agent.parsers.versions import VersionsFromSummaryParser


def test_all_existing_parsers_subclass_base():
    for klass in (
        PurlFromSummaryParser,
        PurlFromCPEParser,
        VersionsFromSummaryParser,
        SeverityFromSummaryParser,
        CWEFromSummaryParser,
    ):
        assert issubclass(klass, BaseParser)
```

- [ ] **Step 7: Run the import test**

Run: `.venv/bin/pytest tests/test_parsers_import.py -v`
Expected: PASS. (These parsers construct an Agent at `__init__`, which calls `OpenAIConfig.from_env()`; this only reads env and does NOT call the LLM, so it works without credentials.)

- [ ] **Step 8: Commit**

```bash
git add agent/parsers/ tests/test_parsers_import.py
git commit -m "refactor(parsers): move existing parsers into agent/parsers/*"
```

---

## Task 9: `prompts.py` — add `PROMPT_CVSS_FROM_SUMMARY`

**Files:**
- Modify: `prompts.py` (append)

**Interfaces:**
- Produces: `PROMPT_CVSS_FROM_SUMMARY` module-level string.

- [ ] **Step 1: Append the prompt to `prompts.py`**

```python
PROMPT_CVSS_FROM_SUMMARY = """You are a Vulnerability Analysis Assistant specialized in CVSS scoring.

Your task: given a vulnerability description, produce the single most accurate
CVSS base vector. Prefer CVSS 3.1 (CVSS:3.1/...) unless the description clearly
requires CVSS 4.0 semantics.

**Rules:**
1. Return ONLY a JSON object with one key "vector" whose value is a complete,
   valid CVSS vector string beginning with "CVSS:3.1/" or "CVSS:4.0/".
2. Include ALL mandatory base metrics. For CVSS 3.1 that is:
   AV, AC, PR, UI, S, C, I, A (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
3. Do NOT include a score; the score is computed from your vector.
4. If the description lacks enough information to choose a metric, choose the
   most defensible value and never omit the metric.

**Output Format (STRICT JSON):**
```json
{{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
```
"""
```

- [ ] **Step 2: Verify it imports**

Run: `.venv/bin/python -c "from prompts import PROMPT_CVSS_FROM_SUMMARY; print(len(PROMPT_CVSS_FROM_SUMMARY))"`
Expected: prints a positive integer.

- [ ] **Step 3: Commit**

```bash
git add prompts.py
git commit -m "feat(prompts): add PROMPT_CVSS_FROM_SUMMARY"
```

---

## Task 10: `agent/parsers/cvss.py` — the new CVSS parser (hybrid)

**Files:**
- Create: `agent/parsers/cvss.py`
- Test: `tests/test_cvss_parser.py`

**Interfaces:**
- Produces: `CVSSFromSummaryParser(BaseParser)` with:
  - `output_type = CVSSVector` but the LLM is asked only for `{"vector": str}`; define a small `CVSSVectorRaw(BaseModel)` with `vector: str` + the `check_valid_cvss` validator (reuse `CVSSVector.check_valid_cvss`), and use that as the `output_type`. The `normalize` hook converts `CVSSVectorRaw` → `CVSSVector` via `CVSSVector.from_vector`.
  - `hooks` property returns `PipelineHooks(preprocess=self._preprocess, normalize=self._normalize)`.
  - `_preprocess(user_prompt)`: run `extract_cvss_vector` on the original summary embedded in the prompt; if found, append an instruction telling the LLM to return exactly that vector (so the LLM path agrees with regex when regex already succeeded). If not found, return the prompt unchanged.
  - `get_cvss(self, summary: str) -> Optional[CVSSVector]`: run the pipeline. If both regex and LLM fail to yield a valid vector, `run_pipeline` will have raised `InvalidOutputError`; catch it and re-raise as `CVSSNotExtractableError`.
  - **Short-circuit:** if `extract_cvss_vector(summary)` succeeds, return `CVSSVector.from_vector(vector)` immediately WITHOUT calling the LLM (the "regex first, skip LLM" path).

> **Clarification of the regex path vs. preprocess hook:** the regex short-circuit happens in `get_cvss` BEFORE the pipeline runs (so no LLM call at all). The `preprocess` hook only matters for the LLM-fallback path, where it nudges the model toward an already-discovered vector if one was partially found. Keep both; the short-circuit is the primary optimization.

- [ ] **Step 1: Write failing test** (stub agent mimicking pydantic-ai's output-validation flow; verify regex short-circuit + LLM fallback + both-fail path)

`tests/test_cvss_parser.py`:
```python
import pytest
from pydantic_ai.exceptions import UnexpectedModelBehavior

from agent.config import RetryPolicy
from agent.models import CVSSVector
from agent.parsers.cvss import CVSSFromSummaryParser, CVSSVectorRaw
from agent.robustness import CVSSNotExtractableError

_VALID_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # base 7.5

_SUMMARY_WITH_VECTOR = f"A flaw allows remote code execution. {_VALID_V31}"
_SUMMARY_WITHOUT_VECTOR = (
    "A flaw allows remote attackers to read arbitrary data over the network "
    "with no privileges or user interaction; confidentiality is fully impacted."
)


class _StubAgent:
    """Mimics pydantic_ai.Agent.run_sync with output_retries=1.

    Tries to construct the output_type (running validators). On the first failure
    it retries once (mirroring output_retries=1); if that also fails it raises
    UnexpectedModelBehavior, exactly as pydantic-ai does.
    """

    def __init__(self, raw_vector: str):
        self._raw_vector = raw_vector
        self.calls = 0

    def run_sync(self, *, user_prompt):
        self.calls += 1
        try:
            validated = CVSSVectorRaw(vector=self._raw_vector)
        except Exception:
            if self.calls <= 1:
                # pydantic-ai would feed the error back and retry once (output_retries=1)
                return self.run_sync(user_prompt=user_prompt)
            raise UnexpectedModelBehavior("Exceeded maximum retries for output validation")

        class _Result:
            output = validated

        return _Result()


def _make_parser(raw_vector: str) -> CVSSFromSummaryParser:
    parser = CVSSFromSummaryParser.__new__(CVSSFromSummaryParser)
    parser._system_prompt = "sys"
    parser.retry_policy = RetryPolicy(max_attempts=1)
    parser.output_type = CVSSVectorRaw
    parser.agent = _StubAgent(raw_vector)
    return parser


def test_regex_short_circuits_and_skips_llm():
    parser = _make_parser(_VALID_V31)
    result = parser.get_cvss(_SUMMARY_WITH_VECTOR)
    assert isinstance(result, CVSSVector)
    assert result.version == "3.1"
    assert result.base_score == 7.5
    assert parser.agent.calls == 0  # LLM never called


def test_llm_fallback_when_no_vector_in_text():
    parser = _make_parser(_VALID_V31)
    result = parser.get_cvss(_SUMMARY_WITHOUT_VECTOR)
    assert isinstance(result, CVSSVector)
    assert result.base_score == 7.5
    assert parser.agent.calls == 1  # first try succeeds


def test_raises_when_both_regex_and_llm_fail():
    # No vector in the summary (regex miss) AND the LLM returns an invalid vector.
    parser = _make_parser("CVSS:3.1/AV:BOGUS/AC:L")
    with pytest.raises(CVSSNotExtractableError):
        parser.get_cvss(_SUMMARY_WITHOUT_VECTOR)
    # output_retries=1 means two model calls before UnexpectedModelBehavior
    assert parser.agent.calls == 2
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/test_cvss_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.parsers.cvss'`.

- [ ] **Step 3: Implement `agent/parsers/cvss.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Hybrid CVSS parser: regex-first extraction, LLM inference fallback."""

from typing import Optional

from pydantic import BaseModel, field_validator

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.cvss_extraction import extract_cvss_vector
from agent.models import CVSSVector
from agent.parsers.base import BaseParser
from agent.pipeline import PipelineHooks
from agent.robustness import CVSSNotExtractableError, InvalidOutputError
from prompts import PROMPT_CVSS_FROM_SUMMARY


class CVSSVectorRaw(BaseModel):
    """LLM output shape: just the vector string. Score is computed, never asked."""

    vector: str

    @field_validator("vector")
    @classmethod
    def check_valid_cvss(cls, v: str) -> str:
        return CVSSVector.check_valid_cvss(v)  # reuse the same validation rules


class CVSSFromSummaryParser(BaseParser):
    _RAW_TYPE = CVSSVectorRaw

    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_CVSS_FROM_SUMMARY, CVSSVectorRaw, retry_policy=retry_policy)

    @property
    def hooks(self) -> PipelineHooks:
        return PipelineHooks(
            preprocess=self._preprocess,
            normalize=self._normalize,
        )

    def _preprocess(self, user_prompt: str) -> str:
        # Nudge the model toward an already-discovered vector if one is embedded.
        found = extract_cvss_vector(user_prompt)
        if found:
            return user_prompt + f"\n\nIf unsure, return exactly this vector: {found}"
        return user_prompt

    def _normalize(self, raw: CVSSVectorRaw) -> CVSSVector:
        return CVSSVector.from_vector(raw.vector)

    def get_cvss(self, summary: str) -> Optional[CVSSVector]:
        # 1. Regex short-circuit: skip the LLM entirely when a valid vector exists.
        found = extract_cvss_vector(summary)
        if found:
            return CVSSVector.from_vector(found)

        # 2. LLM fallback through the pipeline.
        try:
            return self.run_agent(f"**Vulnerability Description:**\n{summary}")
        except InvalidOutputError as err:
            raise CVSSNotExtractableError(raw=err.raw, reason=err.reason) from err
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/test_cvss_parser.py -v`
Expected: PASS (3 tests). `_StubAgent` validates its raw vector by constructing `CVSSVectorRaw` (runs `check_valid_cvss`); the parser's `_normalize` hook then converts it to a `CVSSVector`. For the both-fail case, the stub mirrors pydantic-ai's `output_retries=1` and ultimately raises `UnexpectedModelBehavior`, which the pipeline maps to `InvalidOutputError`, which `get_cvss` re-raises as `CVSSNotExtractableError`.

> **Note on the both-fail test case:** `_StubAgent.run_sync` tries to build `CVSSVectorRaw(vector="CVSS:3.1/AV:BOGUS/AC:L")`. The `check_valid_cvss` validator calls `_parse_cvss_or_raise`, which converts `cvss`'s `CVSS3MalformedError` into a `ValueError` (Task 4 design); pydantic surfaces that as a `ValidationError`, so construction fails. The stub mirrors pydantic-ai's `output_retries=1`: it retries once (second `run_sync` call), still fails, and raises `UnexpectedModelBehavior`. `run_pipeline` translates that to `InvalidOutputError`, which `get_cvss` re-raises as `CVSSNotExtractableError`. Hence `parser.agent.calls == 2`. In the real (non-stub) flow pydantic-ai performs the same retry-then-raise internally, so the pipeline translation is what produces `CVSSNotExtractableError`.

- [ ] **Step 5: Commit**

```bash
git add agent/parsers/cvss.py tests/test_cvss_parser.py
git commit -m "feat(cvss): add hybrid CVSS parser with regex short-circuit"
```

---

## Task 11: Rewrite `agent/__init__.py` — facade + re-exports

**Files:**
- Rewrite: `agent/__init__.py`

**Interfaces:**
- Produces: `VulnerabilityAgent` facade with all existing methods (unchanged signatures) PLUS `get_cvss_from_summary(summary) -> Optional[CVSSVector]`, and optional `retry_policy` constructor parameter. Re-exports all public names so `from agent import Purl, CVSSVector, ...` keeps working.
- Consumes: all parsers from `agent.parsers.*`, models from `agent.models`, `RetryPolicy`/`DEFAULT_RETRY_POLICY` from `agent.config`.

- [ ] **Step 1: Rewrite `agent/__init__.py`**

```python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Public API for the VulnerabilityAgent experiments package."""

from typing import Optional

from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import (
    CWE,
    CWEList,
    CVSSVector,
    Purl,
    Severity,
    SeverityEnum,
    Versions,
)
from agent.parsers.cwe import CWEFromSummaryParser
from agent.parsers.cvss import CVSSFromSummaryParser
from agent.parsers.purl_from_cpe import PurlFromCPEParser
from agent.parsers.purl_from_summary import PurlFromSummaryParser
from agent.parsers.severity import SeverityFromSummaryParser
from agent.parsers.versions import VersionsFromSummaryParser

__all__ = [
    "CWE",
    "CWEList",
    "CVSSVector",
    "Purl",
    "Severity",
    "SeverityEnum",
    "Versions",
    "VulnerabilityAgent",
    "RetryPolicy",
]


class VulnerabilityAgent:
    """Unified interface for parsing vulnerability information.

    Handles extraction of PURLs, version ranges, severities, CWEs, and CVSS
    vectors from vulnerability summaries and CPE identifiers.
    """

    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        self.purl_parser = PurlFromSummaryParser(retry_policy=retry_policy)
        self.versions_parser = VersionsFromSummaryParser(retry_policy=retry_policy)
        self.cpe_parser = PurlFromCPEParser(retry_policy=retry_policy)
        self.severity_parser = SeverityFromSummaryParser(retry_policy=retry_policy)
        self.cwe_parser = CWEFromSummaryParser(retry_policy=retry_policy)
        self.cvss_parser = CVSSFromSummaryParser(retry_policy=retry_policy)

    def get_purl_from_summary(self, summary: str):
        """Extract PURL from a vulnerability summary."""
        return self.purl_parser.get_purl(summary)

    def get_version_ranges(self, summary: str, ecosystem: str):
        """Extract affected/fixed version ranges from a summary."""
        return self.versions_parser.get_version_ranges(summary, ecosystem)

    def get_purl_from_cpe(self, cpe: str, pkg_type: str):
        """Convert a CPE string to a PURL."""
        return self.cpe_parser.get_purl(cpe, pkg_type)

    def get_severity_from_summary(self, summary: str):
        """Extract severity information from a summary."""
        return self.severity_parser.get_severity(summary)

    def get_cwe_from_summary(self, summary: str):
        """Extract CWE IDs from a summary."""
        return self.cwe_parser.get_cwes(summary)

    def get_cvss_from_summary(self, summary: str) -> Optional[CVSSVector]:
        """Extract a CVSS vector (and computed base score) from a summary."""
        return self.cvss_parser.get_cvss(summary)
```

> The parser `__init__` signatures in Task 8/10 already accept and forward `retry_policy`, so the facade can pass `retry_policy` straight through.

- [ ] **Step 2: Smoke-test the public import**

Run: `.venv/bin/python -c "from agent import VulnerabilityAgent, CVSSVector, RetryPolicy; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 3: Commit**

```bash
git add agent/__init__.py agent/parsers/
git commit -m "refactor(agent): rewrite facade with re-exports and get_cvss_from_summary"
```

---

## Task 12: Mark existing live tests + add a live CVSS test

**Files:**
- Modify: `test.py`

**Interfaces:**
- Produces: every existing test in `test.py` decorated with `@pytest.mark.live`; one new parametrized `test_vulnerability_cvss_parser` added at the end.

- [ ] **Step 1: Add the marker import + decorate existing tests**

At the top of `test.py`, after the existing imports, add:
```python
import pytest  # already imported
```
Then add `@pytest.mark.live` directly above each of the four existing parametrized test functions: `test_simple_vulnerability_summary_parser`, `test_vulnerability_cpe_parser_varied_ecosystems`, `test_vulnerability_severity_parser`, `test_vulnerability_cwe_parser`.

- [ ] **Step 2: Append a live CVSS test**

Append to `test.py`:
```python
@pytest.mark.live
@pytest.mark.parametrize(
    "summary, expected_vector_prefix, expected_min_score",
    [
        (
            "A flaw allows remote unauthenticated attackers to execute arbitrary "
            "code over the network without user interaction. CVSS:3.1/"
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.0,
        ),
    ],
)
def test_vulnerability_cvss_parser(summary, expected_vector_prefix, expected_min_score):
    agent = VulnerabilityAgent()
    cvss = agent.get_cvss_from_summary(summary)
    assert cvss is not None
    assert cvss.vector == expected_vector_prefix
    assert cvss.base_score >= expected_min_score
```

- [ ] **Step 3: Verify live tests are skipped by default**

Run: `.venv/bin/pytest -q`
Expected: all `test.py` tests are SKIPPED/deselected (because of `addopts = -m "not live"`); all `tests/` deterministic tests PASS.

- [ ] **Step 4: (Optional, requires live LLM) verify the live CVSS test once**

Run: `.venv/bin/pytest test.py::test_vulnerability_cvss_parser -m live -v`
Expected: PASS (requires valid `OPENAI_*` env).

- [ ] **Step 5: Commit**

```bash
git add test.py
git commit -m "test: mark live tests and add live CVSS parser test"
```

---

## Task 13: Full deterministic suite + README update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the entire deterministic suite**

Run: `.venv/bin/pytest -q`
Expected: all `tests/` PASS; `test.py` (live) deselected.

- [ ] **Step 2: Update `README.md`** — add a "Parsing CVSS" section after the CWE section:

```markdown
## Parsing CVSS

**Get CVSS vector and base score from a summary:**
```bash
summary = "..."
cvss = instance.get_cvss_from_summary(summary)
print(cvss.vector)        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
print(cvss.base_score)    # 7.5
print(cvss.severity_label)# high
```

If the summary already contains an explicit CVSS vector it is extracted directly
(regex) and the score is computed from it; otherwise the LLM infers the vector.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document CVSS parsing in README"
```

---

## Final Verification

- [ ] Run `.venv/bin/pytest -q` — all deterministic tests pass, live tests deselected.
- [ ] Run `.venv/bin/pytest -m live -q` — live tests pass (requires valid `OPENAI_*` env; optional in CI).
- [ ] `from agent import VulnerabilityAgent, CVSSVector, RetryPolicy, Purl, CWE, Severity, Versions` all importable.
- [ ] Every `VulnerabilityAgent` method present in the original repo still exists with the same signature.

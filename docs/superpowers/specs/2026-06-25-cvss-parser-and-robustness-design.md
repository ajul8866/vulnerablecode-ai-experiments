# Design: CVSS Parser + Robustness Layer for VulnerabilityAgent

**Date:** 2026-06-25
**Status:** Approved (brainstorming complete) → ready for implementation plan
**Scope:** Two coupled capabilities — (1) a new CVSS parser, (2) a thorough robustness/error-handling layer applied to all existing parsers plus the new one.

---

## 1. Goals & Non-Goals

### Goals
1. **New CVSS parser** — extract CVSS vector and compute base score (0–10) + severity label from a vulnerability summary, using a **hybrid** strategy: regex extraction of an explicit vector first, LLM inference only as fallback.
2. **Robustness layer (all parsers)** — retry + exponential backoff on transient LLM/network errors, output validation, output normalization, and a single self-correction retry when the LLM returns invalid output. Applied uniformly to every parser (PURL-from-summary, version ranges, PURL-from-CPE, severity, CWE) and to the new CVSS parser.

### Non-Goals (YAGNI)
- No LLM result caching.
- No async / parallelization across parsers (synchronous contract preserved).
- No metrics/telemetry backend — stdlib `logging` at INFO/WARNING only.
- No CVSS v2 support beyond clearly rejecting it.
- No unrelated refactors beyond what serves the two goals.

---

## 2. Architecture — Pipeline in `BaseParser` with per-parser hooks

The robustness behavior is centralized as a pipeline in `BaseParser`. Each concrete parser may contribute optional hooks (`preprocess`, `postprocess`) for parser-specific logic. The CVSS parser registers a `preprocess` hook (regex extraction) and a `postprocess`/`normalize` hook (score computation); the other parsers use the standard pipeline unchanged.

```
VulnerabilityAgent  (facade — public contract unchanged)
└── parser pool  (5 existing parsers + new CVSS parser, each with a pydantic output_type)
    └── BaseParser
        └── centralized pipeline:
            1. preprocess(user_prompt)   [hook, optional — CVSS: regex-extracted vector injected as context]
            2. run_with_retry(prompt)     [retry + exponential backoff on transient error; self-correction loop]
            3. validate_output(result)    [pydantic validation + domain rules, e.g. valid CVSS vector]
            4. normalize_output(result)   [hook, optional — CVSS: compute score from vector via official lib]
```

**Why this shape:** small, isolated units each with one clear purpose, communicating through well-defined interfaces, independently testable. The CVSS hybrid path fits naturally as one pipeline variant rather than a special case, and there is no duplication of retry/validation logic across parsers.

---

## 3. Components

| Component | Responsibility | Dependencies |
|---|---|---|
| `agent/models.py` (new) | Move `Purl`, `CWE`, `CWEList`, `Severity`, `SeverityEnum`, `Versions` out of `__init__.py`; add **`CVSSVector`** (`vector: str`, `version: Literal["2","3.1","4.0"]`, `base_score: float`, `severity_label: str`) with a validator that checks the vector format via the `cvss` library. | pydantic, `cvss` |
| `agent/robustness.py` (new) | Exception hierarchy rooted at `VulnerabilityAgentError`; concrete `LLMUnavailableError`, `InvalidOutputError`, `CVSSNotExtractableError`, `UnsupportedCVSSVersionError`; `RetryPolicy` dataclass (max_attempts, base_delay, max_delay); `with_retry()` util. | stdlib or `tenacity` |
| `agent/pipeline.py` (new) | Orchestration of the 4 pipeline stages; ties retry + single self-correction together (on validation failure, feed the error message back to the LLM once before giving up). | robustness, models |
| `agent/parsers/base.py` (new) | `BaseParser` composing the pipeline; optional hook overrides per subclass. | pipeline, models |
| `agent/parsers/*.py` (new) | One file per concrete parser: `purl_from_summary.py`, `purl_from_cpe.py`, `versions.py`, `severity.py`, `cwe.py`, and **`cvss.py`** (new). | BaseParser, prompts, models |
| `agent/cvss_extraction.py` (new) | `extract_cvss_vector(text) -> Optional[str]`: regex for CVSS 3.1/4.0 vectors → validate → return the vector or `None`. Backbone of the "regex first" path. | `re`, `cvss` |
| `agent/config.py` (new) | `OPENAI_*` env config + `RetryPolicy.DEFAULT` (moved out of `__init__.py`). | stdlib, dotenv |
| `prompts.py` | Add `PROMPT_CVSS_FROM_SUMMARY` (LLM inference of the vector when regex finds nothing). | — |

---

## 4. Data Flow

### Normal path (CVSS)
```
user summary
  │
  ▼ CvssFromSummaryParser.get_cvss(summary)
  │
  ├─[preprocess] extract_cvss_vector(summary)  — regex CVSS:3.1/AV:... | CVSS:4.0/AV:...
  │     ├─ found + VALID ──► skip LLM, go straight to normalize (compute score)
  │     └─ not found / invalid ──► continue to LLM
  │
  ├─[run_with_retry] (only if regex failed)
  │     Agent.run_sync(prompt) → pydantic validates CVSSVector (vector format)
  │     ├─ transient error (timeout/429/conn) ──► backoff, retry ≤ N
  │     └─ invalid output ──► self-correction: feed error message back, retry once
  │
  ├─[validate] vector format + version supported. (When the regex path was taken,
  │            `base_score`/`severity_label` are not yet populated, so they are not
  │            checked here — they are filled in by the next stage.)
  └─[normalize] compute base_score + severity_label from the vector via the `cvss` lib
                → return a fully populated CVSSVector
```

All other parsers traverse the same pipeline but **without** specialized preprocess/normalize hooks — only standard retry + validation.

### Error-handling decision table

| Condition | Behavior | Result to caller |
|---|---|---|
| LLM/transient error (timeout, 429, connection) | `with_retry`: exponential backoff + jitter, ≤ `MAX_ATTEMPTS` (default 3) | Still failing → raise `LLMUnavailableError` |
| LLM output fails pydantic validation | Self-correction: send specific error message back to LLM, retry once | Still failing → `InvalidOutputError` (carries raw text + reason) |
| CVSS regex finds an **invalid** vector (e.g. unknown metric) | Ignore the regex result, fall back to LLM | (transparent) |
| Both regex **and** LLM fail to infer a CVSS | — | `CVSSNotExtractableError` (subclass of `InvalidOutputError`) |
| Valid vector but unsupported version (e.g. CVSS:2) | Validator rejects | `UnsupportedCVSSVersionError` |
| Empty / irrelevant summary input | Pipeline runs; regex will fail so LLM is used | Same as above; may yield `None` if configured |

### Error contract
All custom exceptions subclass a single base `VulnerabilityAgentError` (in `robustness.py`) so callers can catch with one `except`. `MAX_ATTEMPTS` and backoff parameters live on a `RetryPolicy` value (overridable when constructing `VulnerabilityAgent`, with sensible defaults) — no global magic numbers.

---

## 5. Public API (non-breaking additions)

Unchanged:
- `VulnerabilityAgent()` construction.
- `get_purl_from_summary(summary)`, `get_version_ranges(summary, ecosystem)`, `get_purl_from_cpe(cpe, pkg_type)`, `get_severity_from_summary(summary)`, `get_cwe_from_summary(summary)` — signatures and return types unchanged.

New (additive, optional):
- `VulnerabilityAgent.get_cvss_from_summary(summary) -> Optional[CVSSVector]`
- `VulnerabilityAgent(retry_policy: RetryPolicy = RetryPolicy.DEFAULT)` — new optional constructor parameter.

---

## 6. Testing

Two layers so tests can run **without** an LLM (fast, deterministic, CI-friendly), separate from the existing live tests.

| Layer | Coverage | How |
|---|---|---|
| **Deterministic unit** (no LLM) | CVSS regex, vector validator, score computation, normalization, retry/backoff, self-correction | Inject a mock LLM (pydantic-ai `TestModel`/`FunctionModel`, or stub `run_agent`) simulating success, transient-error, invalid-output, then recovery |
| **CVSS integration** | CVSS pipeline end-to-end with a mock | Mock LLM combined with the real regex; assert the "regex hit → skip LLM" path and the "regex miss → LLM fallback" path |
| **Live (optional, existing)** | Current `test.py` calls the real LLM | Mark with pytest marker `@pytest.mark.live`; not run by default CI. The new CVSS parser gets at least one analogous live case |

Config: register the `live` marker and set default `addopts = "-m 'not live'"` (in `pyproject.toml` and/or `conftest.py`) so plain `pytest` never touches the LLM.

---

## 7. Dependencies

| Package | Purpose | Notes |
|---|---|---|
| `cvss` (PyPI) | Parse & compute base score from a CVSS 3.1/4.0 vector; validate metrics | Lightweight, pure-Python, actively maintained |
| Retry/backoff | `with_retry` implementation | **Decision deferred to implementation:** prefer stdlib (`time.sleep` loop) to avoid a new dependency; use `tenacity` only if the team prefers a battle-tested lib |

`requirements.txt` gains `cvss` (and `tenacity` only if not stdlib-based).

---

## 8. File Structure (after)

```
agent/
├── __init__.py            # public re-exports; VulnerabilityAgent contract unchanged
├── models.py              # Purl, CWE, CWEList, Severity, SeverityEnum, Versions + CVSSVector (new)
├── robustness.py          # VulnerabilityAgentError + subclasses, RetryPolicy, with_retry
├── pipeline.py            # pipeline preprocess→run→validate→normalize + self-correction
├── cvss_extraction.py     # extract_cvss_vector(text) — regex + validation (hybrid path)
├── config.py              # OPENAI_* + RetryPolicy default (moved from __init__.py)
└── parsers/
    ├── __init__.py
    ├── base.py            # BaseParser (composes pipeline + optional hooks)
    ├── purl_from_summary.py
    ├── purl_from_cpe.py
    ├── versions.py
    ├── severity.py
    ├── cwe.py
    └── cvss.py            # NEW — preprocess=regex, normalize=score computation
prompts.py                 # + PROMPT_CVSS_FROM_SUMMARY
test.py                    # + @pytest.mark.live marker; new deterministic tests separated
requirements.txt           # + cvss ; (+ tenacity only if not stdlib)
conftest.py                # "live" marker, default addopts -m "not live"
pyproject.toml             # pytest config (if not already present)
docs/superpowers/specs/    # this spec
```

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Refactoring parsers into `agent/parsers/` may affect external code importing `agent.*` directly | Preserve re-exports in `agent/__init__.py` so old import paths keep working |
| The `cvss` library has API variation across versions | Pin minor version in `requirements.txt`; confine all dependency on its API to `cvss_extraction.py` so only one place needs updating |
| Adding the `live` marker stops plain `pytest` from running the existing `test.py` cases | Marker is added to existing cases; run `pytest -m live` for LLM tests, documented in README |

---

## 10. Open Questions (resolved during brainstorming)

| Question | Decision |
|---|---|
| Which new parsing capability? | CVSS vector & score |
| Robustness depth? | Thorough — all parsers |
| CVSS source? | Hybrid: regex first, LLM fallback |
| How to obtain the score? | Compute from the vector via the official `cvss` library |
| Architecture? | C — pipeline in `BaseParser` + optional per-parser hooks |

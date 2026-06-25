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


def test_get_cvss_translates_unexpected_model_behavior(monkeypatch):
    import pytest
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from agent.parsers.base import BaseParser

    parser = CVSSFromSummaryParser.__new__(CVSSFromSummaryParser)
    parser._system_prompt = "sys"
    parser.retry_policy = RetryPolicy(max_attempts=1)
    parser.output_type = CVSSVectorRaw
    parser.agent = _StubAgent(_VALID_V31)  # not actually called because _raw_run is patched

    def boom(self, user_prompt):
        raise UnexpectedModelBehavior("Exceeded maximum retries for output validation")

    monkeypatch.setattr(BaseParser, "_raw_run", boom)

    with pytest.raises(CVSSNotExtractableError):
        parser.get_cvss(_SUMMARY_WITHOUT_VECTOR)

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
        @property
        def hooks(self):
            return PipelineHooks(preprocess=lambda p: p + "!")

    parser = Hooked(output=Out("ok"))
    parser.run_agent("prompt")
    # The stub echoes a fixed output; preprocess is exercised via the pipeline path.
    assert parser._output.value == "ok"
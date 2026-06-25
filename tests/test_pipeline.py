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

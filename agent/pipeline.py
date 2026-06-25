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

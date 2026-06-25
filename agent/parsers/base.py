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

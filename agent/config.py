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
